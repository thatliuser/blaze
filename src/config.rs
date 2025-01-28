// Configuration file shenanigans

use crate::scan::OsType;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::io::Write;
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
    pub pass: String,
    // For Unix, this is the SSH port, and for Windows, this is the SMB port
    pub port: u16,
    pub open_ports: HashSet<u16>,
    pub aliases: HashSet<String>,
    pub os: OsType,
}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    pub hosts: HashMap<IpAddr, Host>,
    pub timeout: Duration,
}

impl ConfigFile {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
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
        pass: String,
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
            .filter(|(_, host)| host.os == OsType::UnixLike)
        {
            let aliases: Vec<_> = host.aliases.iter().cloned().collect();
            let aliases = aliases.join(" ");
            let line = format!(
                "{} {} {} {} {}",
                host.ip, host.user, host.pass, host.port, aliases
            );
            writeln!(writer, "{}", line.trim())?;
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
