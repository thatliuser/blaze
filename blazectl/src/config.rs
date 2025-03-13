// Configuration file shenanigans

use crate::scan::OsType;
use anyhow::Context;
use cidr::IpCidr;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::net::Ipv4Addr;
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::BufReader,
    io::BufWriter,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub user: String,
    pub pass: Option<String>,
    // For Unix, this is the SSH port, and for Windows, this is the SMB port
    pub port: u16,
    pub open_ports: HashSet<u16>,
    pub aliases: HashSet<String>,
    pub os: OsType,
    pub desc: HashSet<String>,
}

impl Host {
    // Either the IP, or a friendly name from profiling.
    pub fn name(&self) -> String {
        self.aliases
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| self.ip.to_string())
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    pub hosts: HashMap<IpAddr, Host>,
    pub cidr: HashSet<IpCidr>,
    // For long tasks like scripts
    pub long_timeout: Duration,
    // For short tasks like TCP connections
    pub short_timeout: Duration,
    // Hosts to ignore in script running across all boxes
    pub excluded_octets: Vec<u8>,
    pub linux_root: String,
    pub windows_root: String,
}

impl ConfigFile {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            cidr: HashSet::new(),
            long_timeout: Duration::from_secs(15),
            short_timeout: Duration::from_millis(150),
            excluded_octets: vec![1, 2],
            linux_root: "root".into(),
            windows_root: "Administrator".into(),
        }
    }
}

pub struct Config {
    file: ConfigFile,
    path: PathBuf,
}

impl Config {
    pub fn new() -> Config {
        Config {
            file: ConfigFile::new(),
            path: PathBuf::from("blaze.yaml"),
        }
    }

    pub fn add_cidr(&mut self, cidr: IpCidr) {
        self.file.cidr.insert(cidr);
    }

    pub fn remove_cidr(&mut self, cidr: IpCidr) {
        self.file.cidr.remove(&cidr);
    }

    pub fn get_cidrs(&self) -> &HashSet<IpCidr> {
        &self.file.cidr
    }

    pub fn from(path: &PathBuf) -> anyhow::Result<Config> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(Config {
            file: serde_yaml::from_reader(reader).context("couldn't parse config file")?,
            path: path.clone(),
        })
    }

    pub fn reload(&mut self) -> anyhow::Result<()> {
        let file = File::open(self.path.clone()).context("couldn't open config file")?;
        let reader = BufReader::new(file);
        let contents: ConfigFile =
            serde_yaml::from_reader(reader).context("couldn't parse config file")?;
        self.file = contents;
        Ok(())
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let file = File::create(&self.path)?;
        let writer = BufWriter::new(file);
        Ok(serde_yaml::to_writer(writer, &self.file)?)
    }

    pub fn host_for_ip(&self, ip: IpAddr) -> Option<&Host> {
        self.file.hosts.get(&ip)
    }

    fn octets_to_ip(octets: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
        if octets.len() > 4 {
            return None;
        }
        let mut ip_arr = [0u8; 4];
        let len = octets.len().min(4);
        ip_arr[4 - len..].copy_from_slice(&octets[..len]);

        let mut mask_arr = [255u8; 4];
        mask_arr[4 - len..].copy_from_slice(&vec![0; len]);

        let ip = Ipv4Addr::from_bits(u32::from_be_bytes(ip_arr));
        let mask = Ipv4Addr::from_bits(u32::from_be_bytes(mask_arr));
        Some((ip, mask))
    }

    // Note: this only works for IPv4
    pub fn host_for_octets(&self, octets: &[u8]) -> Option<&Host> {
        let (ip, mask) = Self::octets_to_ip(octets)?;
        let mut iter = self.get_cidrs().iter().filter_map(|cidr| {
            let cidr = match cidr {
                IpCidr::V4(cidr) => Some(cidr),
                _ => None,
            }?;
            // Get the part of the mask that both IP and CIDR have, to compare them
            let intersect = !mask & cidr.mask();
            (intersect & cidr.first_address() == intersect & ip)
                .then(|| {
                    // Otherwise, the CIDR matches, so try looking up the host
                    let ip = (mask & cidr.first_address()) | (!mask & ip);
                    self.host_for_ip(IpAddr::V4(ip))
                })
                .flatten()
        });
        // There cannot be multiple hosts matching
        iter.next()
            .and_then(|host| iter.next().map_or_else(|| Some(host), |_| None))
    }

    // Allows infering an alias by short name (if no conflicts)
    pub fn host_for_alias(&self, alias: &str) -> Option<&Host> {
        let mut iter = self.hosts().iter().filter_map(|(_, host)| {
            host.aliases
                .iter()
                .any(|a| a.to_lowercase().starts_with(&alias.to_lowercase()))
                .then_some(host)
        });
        // There cannot be multiple hosts matching
        iter.next()
            .and_then(|host| iter.next().map_or_else(|| Some(host), |_| None))
    }

    pub fn get_excluded_octets(&self) -> &Vec<u8> {
        &self.file.excluded_octets
    }

    pub fn set_excluded_octets(&mut self, octets: &Vec<u8>) {
        self.file.excluded_octets = octets.clone()
    }

    pub fn add_host(&mut self, host: &Host) {
        self.file.hosts.insert(host.ip, host.clone());
    }

    pub fn remove_host(&mut self, ip: &IpAddr) -> Option<Host> {
        self.file.hosts.remove(ip)
    }

    pub fn add_host_from(
        &mut self,
        scan_host: &crate::scan::Host,
        user: String,
        pass: Option<String>,
        port: u16,
    ) -> anyhow::Result<()> {
        let host = Host {
            ip: scan_host.addr,
            user,
            pass,
            port,
            open_ports: scan_host.ports.clone(),
            aliases: HashSet::new(),
            os: scan_host.os,
            desc: HashSet::new(),
        };
        self.file.hosts.insert(host.ip, host);
        Ok(())
    }

    pub fn hosts(&self) -> &HashMap<IpAddr, Host> {
        &self.file.hosts
    }

    pub fn script_hosts(&self) -> impl Iterator<Item = (&IpAddr, &Host)> {
        // Filter out hosts that don't have SSH open
        let runnable = self
            .hosts()
            .iter()
            .filter(|(_, host)| host.open_ports.contains(&22));
        runnable.clone().filter(move |(ip, _)| {
            match ip {
                // Get all the addresses that are not part of the excluded octets
                IpAddr::V4(ip) => {
                    let octet = ip.octets()[3];
                    self.get_excluded_octets()
                        .iter()
                        .all(|excluded| excluded != &octet)
                }
                // IDRC about IPv6 since we haven't encountered it in competition
                // Keep it in
                IpAddr::V6(_) => true,
            }
        })
    }

    pub fn export_compat(&self, filename: &Path) -> anyhow::Result<()> {
        let file = File::create(filename)?;
        let mut writer = BufWriter::new(file);
        for (_, host) in self
            .file
            .hosts
            .iter()
            .filter(|(_, host)| host.os == OsType::UnixLike && host.pass.is_some())
        {
            let aliases: Vec<_> = host.aliases.iter().cloned().collect();
            let aliases = aliases.join(" ");
            let line = format!(
                "{} {} {} {} {}",
                host.ip,
                host.user,
                host.pass.as_ref().unwrap(),
                host.port,
                aliases
            );
            writeln!(writer, "{}", line.trim())?;
        }
        Ok(())
    }

    pub fn import_compat(&mut self, filename: &Path) -> anyhow::Result<()> {
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let fields = line.split(" ").collect::<Vec<_>>();
            if fields.len() < 4 {
                anyhow::bail!("invalid line format in legacy file format");
            }
            let ip = fields[0].parse()?;
            let user = fields[1].to_owned();
            let pass = fields[2].to_owned();
            let port: u16 = fields[3].parse()?;
            let aliases = fields[4..].iter().map(|alias| alias.to_string()).collect();
            let host = Host {
                ip,
                user,
                pass: Some(pass),
                port,
                aliases,
                open_ports: HashSet::new(),
                os: OsType::UnixLike,
                desc: HashSet::new(),
            };
            self.add_host(&host);
        }
        Ok(())
    }

    pub fn get_long_timeout(&self) -> Duration {
        self.file.long_timeout
    }

    pub fn set_long_timeout(&mut self, timeout: Duration) {
        self.file.long_timeout = timeout;
    }

    pub fn get_short_timeout(&self) -> Duration {
        self.file.short_timeout
    }

    pub fn set_short_timeout(&mut self, timeout: Duration) {
        self.file.short_timeout = timeout;
    }

    pub fn linux_root(&self) -> &str {
        &self.file.linux_root
    }
    pub fn windows_root(&self) -> &str {
        &self.file.windows_root
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        let _ = self.save();
    }
}
