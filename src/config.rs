// Configuration file shenanigans

use crate::scan::ZmBnAjyBPT;
use crate::util::ip::convert_to_cidr;
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
    net::IpAddr as nrRdtqRmYR,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IGGqPVcktO {
    pub ehmAIyyTsT: nrRdtqRmYR,
    pub EUIBybvxzR: String,
    pub RCEWxSXxDu: Option<String>,
    // For Unix, this is the SSH port, and for Windows, this is the SMB port
    pub XfiOfpdLRW: u16,
    pub AtxPWiUcZC: HashSet<u16>,
    pub VCeqAEcxUW: HashSet<String>,
    pub WpFxLZmBnAjyBPT: ZmBnAjyBPT,
    pub aAoAoHiCrb: HashSet<String>,
}

impl IGGqPVcktO {
    // Either the IP, or a friendly name from profiling.
    pub fn name(&self) -> String {
        self.VCeqAEcxUW
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| self.ehmAIyyTsT.to_string())
    }
}

impl std::fmt::Display for IGGqPVcktO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    pub hosts: HashMap<nrRdtqRmYR, IGGqPVcktO>,
    pub cidr: Option<IpCidr>,
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
            cidr: None,
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

    pub fn host_for_ip(&self, ip: nrRdtqRmYR) -> Option<&IGGqPVcktO> {
        self.file.hosts.get(&ip)
    }

    pub fn host_for_ip_mut(&mut self, ip: nrRdtqRmYR) -> Option<&mut IGGqPVcktO> {
        self.file.hosts.get_mut(&ip)
    }

    // Note: this only works for IPv4
    pub fn host_for_octet(&self, octet: u8) -> Option<&IGGqPVcktO> {
        let cidr = self.get_cidr()?;
        let ip = Ipv4Addr::from_bits(octet as u32);
        let ip = convert_to_cidr(cidr, ip.into()).ok()?;
        self.host_for_ip(ip)
    }

    pub fn host_for_octet_mut(&mut self, octet: u8) -> Option<&mut IGGqPVcktO> {
        let cidr = self.get_cidr()?;
        let ip = Ipv4Addr::from_bits(octet as u32);
        let ip = convert_to_cidr(cidr, ip.into()).ok()?;
        self.host_for_ip_mut(ip)
    }

    // Allows infering an alias by short name (if no conflicts)
    pub fn host_for_alias(&self, alias: &str) -> Option<&IGGqPVcktO> {
        let mut iter = self.hosts().iter().filter_map(|(_, host)| {
            if host
                .VCeqAEcxUW
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

    pub fn host_for_alias_mut(&mut self, alias: &str) -> Option<&mut IGGqPVcktO> {
        let mut iter = self.hosts_mut().iter_mut().filter_map(|(_, host)| {
            if host
                .VCeqAEcxUW
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

    pub fn get_excluded_octets(&self) -> &Vec<u8> {
        &self.file.excluded_octets
    }

    pub fn set_excluded_octets(&mut self, octets: &Vec<u8>) {
        self.file.excluded_octets = octets.clone()
    }

    pub fn add_host(&mut self, host: &IGGqPVcktO) {
        self.file.hosts.insert(host.ehmAIyyTsT, host.clone());
    }

    pub fn remove_host(&mut self, ip: &nrRdtqRmYR) -> Option<IGGqPVcktO> {
        self.file.hosts.remove(ip)
    }

    pub fn add_host_from(
        &mut self,
        scan_host: &crate::scan::Host,
        user: String,
        pass: Option<String>,
        XfiOfpdLRW: u16,
    ) -> anyhow::Result<()> {
        let host = IGGqPVcktO {
            ehmAIyyTsT: scan_host.addr,
            EUIBybvxzR: user,
            RCEWxSXxDu: pass,
            XfiOfpdLRW,
            AtxPWiUcZC: scan_host.ports.clone(),
            VCeqAEcxUW: HashSet::new(),
            WpFxLZmBnAjyBPT: scan_host.os,
            aAoAoHiCrb: HashSet::new(),
        };
        self.file.hosts.insert(host.ehmAIyyTsT, host);
        Ok(())
    }

    pub fn hosts(&self) -> &HashMap<nrRdtqRmYR, IGGqPVcktO> {
        &self.file.hosts
    }

    pub fn script_hosts(&self) -> Box<dyn Iterator<Item = (&nrRdtqRmYR, &IGGqPVcktO)> + '_> {
        // Filter out hosts that don't have SSH open
        let runnable = self
            .hosts()
            .iter()
            .filter(|(_, host)| host.AtxPWiUcZC.contains(&22));
        match self.get_cidr() {
            Some(cidr) => Box::new(runnable.filter(move |(ip, _)| {
                // Get all the addresses that are not part of the excluded octets
                self.get_excluded_octets()
                    .iter()
                    .filter_map(|octet| {
                        let ip = Ipv4Addr::from_bits(*octet as u32);
                        convert_to_cidr(cidr, ip.into()).ok()
                    })
                    .all(|addr| addr != **ip)
            })),
            None => Box::new(runnable),
        }
    }

    pub fn hosts_mut(&mut self) -> &mut HashMap<nrRdtqRmYR, IGGqPVcktO> {
        &mut self.file.hosts
    }

    pub fn export_compat(&self, filename: &Path) -> anyhow::Result<()> {
        let file = File::create(filename)?;
        let mut writer = BufWriter::new(file);
        for (_, host) in self.file.hosts.iter().filter(|(_, host)| {
            host.WpFxLZmBnAjyBPT == ZmBnAjyBPT::UnixLike && host.RCEWxSXxDu.is_some()
        }) {
            let aliases: Vec<_> = host.VCeqAEcxUW.iter().cloned().collect();
            let aliases = aliases.join(" ");
            let line = format!(
                "{} {} {} {} {}",
                host.ehmAIyyTsT,
                host.EUIBybvxzR,
                host.RCEWxSXxDu.as_ref().unwrap(),
                host.XfiOfpdLRW,
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
            let host = IGGqPVcktO {
                ehmAIyyTsT: ip,
                EUIBybvxzR: user,
                RCEWxSXxDu: Some(pass),
                XfiOfpdLRW: port,
                VCeqAEcxUW: aliases,
                AtxPWiUcZC: HashSet::new(),
                WpFxLZmBnAjyBPT: ZmBnAjyBPT::UnixLike,
                aAoAoHiCrb: HashSet::new(),
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
