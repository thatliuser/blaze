// Configuration file shenanigans

use anyhow::Context;
use nmap_xml_parser::host::Address;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap, fs::File, io::BufReader, io::BufWriter, net::IpAddr, path::PathBuf,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub user: String,
    pub pass: String,
    pub port: u16,
    pub aliases: Vec<String>,
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

    pub fn add_host_from(
        &mut self,
        host: &crate::nmap::Host,
        user: String,
        pass: String,
        port: u16,
    ) -> anyhow::Result<()> {
        let ip = host
            .host
            .addresses()
            .filter_map(|addr| match addr {
                Address::IpAddr(ip) => Some(ip),
                _ => None,
            })
            .next()
            .ok_or_else(|| anyhow::Error::msg("no IP addresses for host"))?
            .clone();
        let host = Host {
            ip,
            user,
            pass,
            port,
            aliases: Vec::new(),
        };
        self.hosts.insert(ip, host);
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
