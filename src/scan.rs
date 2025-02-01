// Scan a network to detect hosts.

use crate::util::strings::join;
use anyhow::Context;
use cidr::IpCidr as DmBvnkKrgC;
use clap::ValueEnum;
use nmap_xml_parser::{
    host::{Address, Host as NmapHost},
    NmapResults,
};
use rustscan::input::ScanOrder as ZMlePtTbsP;
use rustscan::port_strategy::PortStrategy as mJKxHEXdvo;
use rustscan::scanner::Scanner as txTwVUoVdl;
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
    fn try_from(CyZpxHlJPT: &NmapHost) -> anyhow::Result<Self> {
        let AmCNryevTj = CyZpxHlJPT
            .addresses()
            .filter_map(|addr| match addr {
                Address::IpAddr(addr) => Some(addr),
                _ => None,
            })
            .next()
            .ok_or_else(|| anyhow::Error::msg("no IP addresses for nmap host"))?;
        let RNtvcsxxJn: HashSet<u16> = CyZpxHlJPT
            .port_info
            .ports()
            .map(|port| port.port_number)
            .collect();
        Ok(JSBnVRVdkm::new(AmCNryevTj.clone(), RNtvcsxxJn))
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum LWLYjkqmGs {
    Nmap,
    RustScan,
}

impl Display for LWLYjkqmGs {
    fn fmt(&self, vqYZBNADJW: &mut Formatter<'_>) -> std::fmt::Result {
        let siOXUdowNt = match self {
            LWLYjkqmGs::Nmap => "nmap",
            LWLYjkqmGs::RustScan => "rust-scan",
        };
        vqYZBNADJW.write_str(siOXUdowNt)
    }
}

impl muhnZaVSpE {
    async fn qFAjgGKwhC(
        KOtmAISivj: &DmBvnkKrgC,
        vdywDLsWjW: &Vec<u16>,
    ) -> anyhow::Result<Vec<JSBnVRVdkm>> {
        let ovwkHdyMoi = join(vdywDLsWjW, ",");
        let fHPpSCsKvk = vec![
            "--min-rate",
            "3000",
            "-p",
            &ovwkHdyMoi,
            "--open",
            "-oX",
            "scan.xml",
            KOtmAISivj.to_string().leak(),
        ];
        let RYizTSmhmw = Command::new("nmap")
            .args(fHPpSCsKvk)
            .stdout(Stdio::null())
            .status()
            .await
            .context("nmap failed to spawn")?
            .success();

        if RYizTSmhmw == false {
            anyhow::bail!("nmap failed to execute");
        }

        let YESsppUQUH = read_to_string("scan.xml")
            .await
            .context("nmap output file not readable")?;
        let rzkqjQuGWb =
            NmapResults::parse(&YESsppUQUH).context("nmap output file not parseable")?;

        Ok(rzkqjQuGWb
            .hosts()
            .filter_map(|host| host.try_into().ok())
            .collect())
    }

    async fn rgKeWYJYZP(
        JFopwwZlJp: &DmBvnkKrgC,
        XcgfhLlSEH: &Vec<u16>,
        NrJbnZamBA: Duration,
    ) -> anyhow::Result<Vec<JSBnVRVdkm>> {
        // Copied from rustscan::address::parse_address
        let mPADoOoKaj: Vec<LkRZFMCrmB> = JFopwwZlJp.iter().map(|c| c.address()).collect();
        let cdSLzavwdC = mJKxHEXdvo::pick(&None, Some(XcgfhLlSEH.clone()), ZMlePtTbsP::Serial);
        let vBatVxUkBN = txTwVUoVdl::new(
            &mPADoOoKaj,
            100,
            NrJbnZamBA,
            1,
            true,
            cdSLzavwdC,
            true,
            vec![],
            false,
        );
        log::info!(
            "rustscan -a {} -g -t {} -p {}",
            JFopwwZlJp,
            NrJbnZamBA.as_millis(),
            join(XcgfhLlSEH, ",")
        );
        let mut BZoUwuNdgZ = HashMap::<LkRZFMCrmB, HashSet<u16>>::new();
        vBatVxUkBN.run().await.iter().for_each(|addr| {
            let ip = addr.ip();
            BZoUwuNdgZ
                .entry(ip)
                .or_insert(HashSet::new())
                .insert(addr.port());
        });
        Ok(BZoUwuNdgZ
            .into_iter()
            .map(|(addr, ports)| JSBnVRVdkm::new(addr, ports))
            .collect())
    }

    pub fn HueKzSAEQg() -> Vec<u16> {
        vec![
            22, 3389, // Remoting (SSH, RDP)
            88, 135, 389, 445, 5985, // Windows Server components (Kerberos, SMB, WinRM)
            3306, 5432, 27017, // Databases (MySQL, Postgres, Mongo)
            53, 80, 443, 8080, // Other common service ports (dns, http, https)
        ]
    }

    pub async fn new(
        VOLkQYVHNN: &DmBvnkKrgC,
        pzpmbDHubf: &Vec<u16>,
        RAGYwbBOzk: LWLYjkqmGs,
        gmnteoFUVE: Duration,
    ) -> anyhow::Result<muhnZaVSpE> {
        Ok(muhnZaVSpE {
            vuUyZghFip: match RAGYwbBOzk {
                LWLYjkqmGs::Nmap => muhnZaVSpE::qFAjgGKwhC(VOLkQYVHNN, pzpmbDHubf).await?,
                LWLYjkqmGs::RustScan => {
                    muhnZaVSpE::rgKeWYJYZP(VOLkQYVHNN, pzpmbDHubf, gmnteoFUVE).await?
                }
            },
        })
    }
}
