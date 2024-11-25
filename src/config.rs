// Configuration file shenanigans

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::BufReader,
    io::BufWriter,
    net::IpAddr,
    path::PathBuf,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub user: String,
    pub pass: String,
    pub port: u16,
    pub aliases: HashSet<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    hosts: HashMap<IpAddr, Host>,
    path: PathBuf,
}

impl Config {
    pub fn new() -> Config {
        Config {
            hosts: HashMap::new(),
            path: PathBuf::from("blaze.yaml"),
        }
    }

    pub fn from(path: &PathBuf) -> anyhow::Result<Config> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(Config {
            hosts: serde_yaml::from_reader(reader).context("couldn't parse config file")?,
            path: path.clone(),
        })
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let file = File::create(&self.path)?;
        let writer = BufWriter::new(file);
        Ok(serde_yaml::to_writer(writer, &self.hosts)?)
    }

    pub fn host_for_ip(&self, ip: IpAddr) -> Option<&Host> {
        self.hosts.get(&ip)
    }

    pub fn host_for_alias(&self, alias: &String) -> Option<&Host> {
        self.hosts()
            .iter()
            .filter_map(|(_, host)| {
                if host.aliases.iter().any(|a| &a.to_lowercase() == alias) {
                    Some(host)
                } else {
                    None
                }
            })
            .next()
    }

    pub fn add_host(&mut self, host: &Host) {
        self.hosts.insert(host.ip, host.clone());
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
            aliases: HashSet::new(),
        };
        self.hosts.insert(host.ip, host);
        Ok(())
    }

    pub fn hosts(&self) -> &HashMap<IpAddr, Host> {
        &self.hosts
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        let _ = self.save();
    }
}
