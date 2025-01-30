// Configuration file shenanigans

use crate::scan::OsType;
use anyhow::Context;
use cidr::IpCidr;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
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
}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    pub hosts: HashMap<IpAddr, Host>,
    pub cidr: Option<IpCidr>,
    pub timeout: Duration,
}

impl ConfigFile {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            cidr: None,
            timeout: Duration::from_secs(15),
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

    pub fn set_cidr(&mut self, cidr: IpCidr) {
        self.file.cidr = Some(cidr);
    }

    pub fn get_cidr(&self) -> Option<IpCidr> {
        self.file.cidr
    }

    pub fn from(path: &PathBuf) -> anyhow::Result<Config> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(Config {
            file: serde_yaml::from_reader(reader).context("couldn't parse config file")?,
            path: path.clone(),
        })
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let file = File::create(&self.path)?;
        let writer = BufWriter::new(file);
        Ok(serde_yaml::to_writer(writer, &self.file)?)
    }

    pub fn host_for_ip(&self, ip: IpAddr) -> Option<&Host> {
        self.file.hosts.get(&ip)
    }

    pub fn host_for_ip_mut(&mut self, ip: IpAddr) -> Option<&mut Host> {
        self.file.hosts.get_mut(&ip)
    }

    // Allows infering an alias by short name (if no conflicts)
    pub fn host_for_alias(&self, alias: &str) -> Option<&Host> {
        let mut iter = self.hosts().iter().filter_map(|(_, host)| {
            if host
                .aliases
                .iter()
                .any(|a| a.to_lowercase().starts_with(&alias.to_lowercase()))
            {
                Some(host)
            } else {
                None
            }
        });
        iter.next().and_then(|host| {
            if let Some(_) = iter.next() {
                None
            } else {
                Some(host)
            }
        })
    }

    pub fn host_for_alias_mut(&mut self, alias: &str) -> Option<&mut Host> {
        let mut iter = self.hosts_mut().iter_mut().filter_map(|(_, host)| {
            if host
                .aliases
                .iter()
                .any(|a| a.to_lowercase().starts_with(&alias.to_lowercase()))
            {
                Some(host)
            } else {
                None
            }
        });
        iter.next().and_then(|host| {
            if let Some(_) = iter.next() {
                None
            } else {
                Some(host)
            }
        })
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
        };
        self.file.hosts.insert(host.ip, host);
        Ok(())
    }

    pub fn hosts(&self) -> &HashMap<IpAddr, Host> {
        &self.file.hosts
    }

    pub fn hosts_mut(&mut self) -> &mut HashMap<IpAddr, Host> {
        &mut self.file.hosts
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
            };
            self.add_host(&host);
        }
        Ok(())
    }

    pub fn get_timeout(&self) -> Duration {
        self.file.timeout
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.file.timeout = timeout;
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        let _ = self.save();
    }
}
