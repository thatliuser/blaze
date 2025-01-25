// Scan a network to detect hosts.

use crate::ssh::Session;
use anyhow::Context;
use cidr::IpCidr;
use clap::ValueEnum;
use nmap_xml_parser::{
    host::{Address, Host as NmapHost},
    NmapResults,
};
use rustscan::input::ScanOrder;
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::Scanner;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
    net::IpAddr,
    process::Stdio,
    time::Duration,
};
use tokio::{fs::read_to_string, process::Command};

#[derive(Clone, Debug)]
pub struct Scan {
    pub hosts: Vec<Host>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum OsType {
    #[value(alias("unix"))]
    UnixLike,
    #[value(alias("win"))]
    Windows,
}

#[derive(Clone, Debug)]
pub struct Host {
    pub addr: IpAddr,
    pub ports: HashSet<u16>,
    pub os: OsType,
}

impl Host {
    pub fn new(addr: IpAddr, ports: HashSet<u16>) -> Host {
        let os = if ports.iter().any(|port| port == &3389) {
            OsType::Windows
        } else {
            OsType::UnixLike
        };
        Host { addr, ports, os }
    }
    // Check the SSH server ID to get the OS type
    pub async fn try_detect_ssh(&self, timeout: Duration) -> anyhow::Result<(String, OsType)> {
        let id = Session::get_server_id((self.addr, 22), timeout).await?;
        let os = if id.to_lowercase().contains("windows") {
            OsType::Windows
        } else {
            OsType::UnixLike
        };
        Ok((id, os))
    }
}

impl TryFrom<&NmapHost> for Host {
    type Error = anyhow::Error;
    fn try_from(nmap: &NmapHost) -> anyhow::Result<Self> {
        let addr = nmap
            .addresses()
            .filter_map(|addr| match addr {
                Address::IpAddr(addr) => Some(addr),
                _ => None,
            })
            .next()
            .ok_or_else(|| anyhow::Error::msg("no IP addresses for nmap host"))?;
        let ports: HashSet<u16> = nmap
            .port_info
            .ports()
            .map(|port| port.port_number)
            .collect();
        Ok(Host::new(addr.clone(), ports))
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum Backend {
    Nmap,
    RustScan,
}

impl Display for Backend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Backend::Nmap => "nmap",
            Backend::RustScan => "rust-scan",
        };
        f.write_str(str)
    }
}

impl Scan {
    async fn nmap(subnet: &IpCidr) -> anyhow::Result<Vec<Host>> {
        let args = vec![
            "--min-rate",
            "3000",
            "-p",
            "22,88,135,389,445,3389,5985",
            "--open",
            "-oX",
            "scan.xml",
            subnet.to_string().leak(),
        ];
        let result = Command::new("nmap")
            .args(args)
            .stdout(Stdio::null())
            .status()
            .await
            .context("nmap failed to spawn")?
            .success();

        if result == false {
            anyhow::bail!("nmap failed to execute");
        }

        let file = read_to_string("scan.xml")
            .await
            .context("nmap output file not readable")?;
        let scan = NmapResults::parse(&file).context("nmap output file not parseable")?;

        Ok(scan
            .hosts()
            .filter_map(|host| host.try_into().ok())
            .collect())
    }

    async fn rustscan(subnet: &IpCidr) -> anyhow::Result<Vec<Host>> {
        // Copied from rustscan::address::parse_address
        let ips: Vec<IpAddr> = subnet.iter().map(|c| c.address()).collect();
        let ports = vec![22u16, 88, 135, 389, 445, 3389, 5985];
        let strategy = PortStrategy::pick(&None, Some(ports.clone()), ScanOrder::Serial);
        let timeout_ms = 100;
        let scanner = Scanner::new(
            &ips,
            100,
            Duration::from_millis(timeout_ms),
            1,
            true,
            strategy,
            true,
            vec![],
            false,
        );
        log::info!(
            "rustscan -a {} -g -t {} -p {}",
            subnet,
            timeout_ms,
            ports
                .iter()
                .map(|port| port.to_string())
                .collect::<Vec<String>>()
                .join(","),
        );
        let mut hosts = HashMap::<IpAddr, HashSet<u16>>::new();
        scanner.run().await.iter().for_each(|addr| {
            let ip = addr.ip();
            hosts
                .entry(ip)
                .or_insert(HashSet::new())
                .insert(addr.port());
        });
        Ok(hosts
            .into_iter()
            .map(|(addr, ports)| Host::new(addr, ports))
            .collect())
    }

    pub async fn new(subnet: &IpCidr, backend: Backend) -> anyhow::Result<Scan> {
        Ok(Scan {
            hosts: match backend {
                Backend::Nmap => Scan::nmap(subnet).await?,
                Backend::RustScan => Scan::rustscan(subnet).await?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nmap() -> anyhow::Result<()> {
        Scan::new(&"10.100.3.0/24".parse().unwrap(), Backend::Nmap)
            .await
            .map(|_| ())
    }

    #[tokio::test]
    async fn test_rustscan() -> anyhow::Result<()> {
        Scan::new(&"10.100.3.0/24".parse().unwrap(), Backend::RustScan)
            .await
            .map(|_| ())
    }
}
