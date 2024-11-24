use anyhow::Context;
use nmap_xml_parser::{host::Host, NmapResults};
use serde::Deserialize;
use std::{
    fs::read_to_string,
    process::{Command, Stdio},
};

#[derive(Clone, Debug)]
struct Scan {
    results: NmapResults,
}

#[derive(Clone, Debug)]
enum OsType {
    UnixLike,
    Windows,
}

#[derive(Clone, Debug)]
struct CategorizedHost {
    pub host: Host,
    pub os: OsType,
}

impl Scan {
    fn new(subnet: impl Into<String>) -> anyhow::Result<Scan> {
        let args = vec![
            "--min-rate",
            "3000",
            "-p",
            "22,88,135,389,445,3389,5985",
            "--open",
            "-oX",
            "scan.xml",
            subnet.into().leak(),
        ];
        let result = Command::new("nmap")
            .args(args)
            .stdout(Stdio::null())
            .status()
            .context("nmap failed to spawn")?
            .success();

        if result == false {
            anyhow::bail!("nmap failed to execute");
        }

        let file = read_to_string("scan.xml").context("nmap output file not readable")?;
        let scan = NmapResults::parse(&file).context("nmap output file not parseable")?;

        Ok(Scan { results: scan })
    }

    fn get_categorized_hosts(&self) -> Vec<CategorizedHost> {
        // Hosts with RDP are most likely windows
        self.results
            .hosts()
            .map(|host| {
                let mut ports = host.port_info.ports();
                if ports.any(|port| port.port_number == 3389) {
                    // Hosts with RDP are almost definitely Windows
                    CategorizedHost {
                        host: host.clone(),
                        os: OsType::Windows,
                    }
                } else {
                    // There's like, no other options so just assume Linux/BSD/whatever
                    CategorizedHost {
                        host: host.clone(),
                        os: OsType::UnixLike,
                    }
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_fast() -> anyhow::Result<()> {
        let scan = Scan::new("10.100.3.0/24")?;
        let hosts = scan.get_categorized_hosts();
        for host in hosts.iter() {
            println!("{:?}: {:?}", host.host.addresses(), host.os);
        }
        Ok(())
    }
}
