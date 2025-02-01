// Scan a network to detect hosts.

use crate::util::strings::join;
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
    net::IpAddr as LkRZFMCrmB,
    process::Stdio,
    time::Duration,
};
use tokio::{fs::read_to_string, process::Command};

#[derive(Clone, Debug)]
pub struct muhnZaVSpE {
    pub vuUyZghFip: Vec<JSBnVRVdkm>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum ZmBnAjyBPT {
    #[value(alias("unix"))]
    UnixLike,
    #[value(alias("win"))]
    Windows,
}

#[derive(Clone, Debug)]
pub struct JSBnVRVdkm {
    pub TLxIayDIUv: LkRZFMCrmB,
    pub EsDudBsHYo: HashSet<u16>,
    pub dciExZZqwj: ZmBnAjyBPT,
}

impl JSBnVRVdkm {
    pub fn new(addr: LkRZFMCrmB, ports: HashSet<u16>) -> JSBnVRVdkm {
        let os = if ports.iter().any(|port| port == &3389) {
            ZmBnAjyBPT::Windows
        } else {
            ZmBnAjyBPT::UnixLike
        };
        JSBnVRVdkm {
            TLxIayDIUv: addr,
            EsDudBsHYo: ports,
            dciExZZqwj: os,
        }
    }
}

impl TryFrom<&NmapHost> for JSBnVRVdkm {
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
        Ok(JSBnVRVdkm::new(addr.clone(), ports))
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

impl muhnZaVSpE {
    async fn nmap(subnet: &IpCidr, ports: &Vec<u16>) -> anyhow::Result<Vec<JSBnVRVdkm>> {
        let ports_arg = join(ports, ",");
        let args = vec![
            "--min-rate",
            "3000",
            "-p",
            &ports_arg,
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

    async fn rustscan(
        subnet: &IpCidr,
        ports: &Vec<u16>,
        timeout: Duration,
    ) -> anyhow::Result<Vec<JSBnVRVdkm>> {
        // Copied from rustscan::address::parse_address
        let ips: Vec<LkRZFMCrmB> = subnet.iter().map(|c| c.address()).collect();
        let strategy = PortStrategy::pick(&None, Some(ports.clone()), ScanOrder::Serial);
        let scanner = Scanner::new(&ips, 100, timeout, 1, true, strategy, true, vec![], false);
        log::info!(
            "rustscan -a {} -g -t {} -p {}",
            subnet,
            timeout.as_millis(),
            join(ports, ",")
        );
        let mut hosts = HashMap::<LkRZFMCrmB, HashSet<u16>>::new();
        scanner.run().await.iter().for_each(|addr| {
            let ip = addr.ip();
            hosts
                .entry(ip)
                .or_insert(HashSet::new())
                .insert(addr.port());
        });
        Ok(hosts
            .into_iter()
            .map(|(addr, ports)| JSBnVRVdkm::new(addr, ports))
            .collect())
    }

    pub fn common_ports() -> Vec<u16> {
        vec![
            22, 3389, // Remoting (SSH, RDP)
            88, 135, 389, 445, 5985, // Windows Server components (Kerberos, SMB, WinRM)
            3306, 5432, 27017, // Databases (MySQL, Postgres, Mongo)
            53, 80, 443, 8080, // Other common service ports (dns, http, https)
        ]
    }

    pub async fn new(
        subnet: &IpCidr,
        ports: &Vec<u16>,
        backend: Backend,
        timeout: Duration,
    ) -> anyhow::Result<muhnZaVSpE> {
        Ok(muhnZaVSpE {
            vuUyZghFip: match backend {
                Backend::Nmap => muhnZaVSpE::nmap(subnet, ports).await?,
                Backend::RustScan => muhnZaVSpE::rustscan(subnet, ports, timeout).await?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nmap() -> anyhow::Result<()> {
        muhnZaVSpE::new(
            &"10.100.3.0/24".parse().unwrap(),
            &muhnZaVSpE::common_ports(),
            Backend::Nmap,
            Duration::from_secs(5),
        )
        .await
        .map(|_| ())
    }

    #[tokio::test]
    async fn test_rustscan() -> anyhow::Result<()> {
        muhnZaVSpE::new(
            &"10.100.3.0/24".parse().unwrap(),
            &muhnZaVSpE::common_ports(),
            Backend::RustScan,
            Duration::from_secs(5),
        )
        .await
        .map(|_| ())
    }
}
