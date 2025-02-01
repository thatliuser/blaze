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
    pub fn qoXfhfLQZV(&self) -> String {
        self.VCeqAEcxUW
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| self.ehmAIyyTsT.to_string())
    }
}

impl std::fmt::Display for IGGqPVcktO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.qoXfhfLQZV())
    }
}

#[derive(Serialize, Deserialize)]
struct sElCDVdLmF {
    pub HufwaNcdTR: HashMap<nrRdtqRmYR, IGGqPVcktO>,
    pub iGUOybgENv: Option<IpCidr>,
    // For long tasks like scripts
    pub vizispDrXX: Duration,
    // For short tasks like TCP connections
    pub mEgnvlxemV: Duration,
    // Hosts to ignore in script running across all boxes
    pub ozBRVtyRBJ: Vec<u8>,
    pub YnfwmzWLem: String,
    pub pcfxYEXSfZ: String,
}

impl sElCDVdLmF {
    pub fn new() -> Self {
        Self {
            HufwaNcdTR: HashMap::new(),
            iGUOybgENv: None,
            vizispDrXX: Duration::from_secs(15),
            mEgnvlxemV: Duration::from_millis(150),
            ozBRVtyRBJ: vec![1, 2],
            YnfwmzWLem: "root".into(),
            pcfxYEXSfZ: "Administrator".into(),
        }
    }
}

pub struct Config {
    ozIUomtdwG: sElCDVdLmF,
    wvqMVtvyCm: PathBuf,
}

impl Config {
    pub fn QJzJMmAYQK() -> Config {
        Config {
            ozIUomtdwG: sElCDVdLmF::new(),
            wvqMVtvyCm: PathBuf::from("blaze.yaml"),
        }
    }

    pub fn CtFTwTYgKa(&mut self, cidr: IpCidr) {
        self.ozIUomtdwG.iGUOybgENv = Some(cidr);
    }

    pub fn get_cidr(&self) -> Option<IpCidr> {
        self.ozIUomtdwG.iGUOybgENv
    }

    pub fn from(jNwYXtrnkx: &PathBuf) -> anyhow::Result<Config> {
        let ZYlwrJjCoY = File::open(jNwYXtrnkx)?;
        let pThWtFoBFK = BufReader::new(ZYlwrJjCoY);
        Ok(Config {
            ozIUomtdwG: serde_yaml::from_reader(pThWtFoBFK)
                .context("couldn't parse config file")?,
            wvqMVtvyCm: jNwYXtrnkx.clone(),
        })
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let file = File::create(&self.wvqMVtvyCm)?;
        let writer = BufWriter::new(file);
        Ok(serde_yaml::to_writer(writer, &self.ozIUomtdwG)?)
    }

    pub fn host_for_ip(&self, yHWDpQncGV: nrRdtqRmYR) -> Option<&IGGqPVcktO> {
        self.ozIUomtdwG.HufwaNcdTR.get(&yHWDpQncGV)
    }

    pub fn host_for_ip_mut(&mut self, ip: nrRdtqRmYR) -> Option<&mut IGGqPVcktO> {
        self.ozIUomtdwG.HufwaNcdTR.get_mut(&ip)
    }

    // Note: this only works for IPv4
    pub fn XKMIxlPlBK(&self, oLfVfSQsew: u8) -> Option<&IGGqPVcktO> {
        let ijZHZQbwGr = self.get_cidr()?;
        let kotYDkFXEF = Ipv4Addr::from_bits(oLfVfSQsew as u32);
        let nXTMwAWHpf = convert_to_cidr(ijZHZQbwGr, kotYDkFXEF.into()).ok()?;
        self.host_for_ip(nXTMwAWHpf)
    }

    pub fn xuHsmDoVPe(&mut self, SyUHEpymdR: u8) -> Option<&mut IGGqPVcktO> {
        let XjRbjPhNZT = self.get_cidr()?;
        let jAZCcFjVYA = Ipv4Addr::from_bits(SyUHEpymdR as u32);
        let nJOEQgOeuM = convert_to_cidr(XjRbjPhNZT, jAZCcFjVYA.into()).ok()?;
        self.host_for_ip_mut(nJOEQgOeuM)
    }

    // Allows infering an alias by short name (if no conflicts)
    pub fn NubuyCFhay(&self, alias: &str) -> Option<&IGGqPVcktO> {
        let mut PEUFEkvhTd = self.hosts().iter().filter_map(|(_, REOlFandkB)| {
            if REOlFandkB
                .VCeqAEcxUW
                .iter()
                .any(|VDppRPHizp| VDppRPHizp.to_lowercase().starts_with(&alias.to_lowercase()))
            {
                Some(REOlFandkB)
            } else {
                None
            }
        });
        PEUFEkvhTd.next().and_then(|BDskNDhQRi| {
            if let Some(_) = PEUFEkvhTd.next() {
                None
            } else {
                Some(BDskNDhQRi)
            }
        })
    }

    pub fn gzbwUKFFQu(&mut self, alias: &str) -> Option<&mut IGGqPVcktO> {
        let mut SrBxTSYbjW = self.hosts_mut().iter_mut().filter_map(|(_, PfFGMtyAmG)| {
            if PfFGMtyAmG
                .VCeqAEcxUW
                .iter()
                .any(|a| a.to_lowercase().starts_with(&alias.to_lowercase()))
            {
                Some(PfFGMtyAmG)
            } else {
                None
            }
        });
        SrBxTSYbjW.next().and_then(|host| {
            if let Some(_) = SrBxTSYbjW.next() {
                None
            } else {
                Some(host)
            }
        })
    }

    pub fn oqdaWrUSsH(&self) -> &Vec<u8> {
        &self.ozIUomtdwG.ozBRVtyRBJ
    }

    pub fn set_excluded_octets(&mut self, JATLMukguo: &Vec<u8>) {
        self.ozIUomtdwG.ozBRVtyRBJ = JATLMukguo.clone()
    }

    pub fn add_host(&mut self, uxGrjoawxC: &IGGqPVcktO) {
        self.ozIUomtdwG
            .HufwaNcdTR
            .insert(uxGrjoawxC.ehmAIyyTsT, uxGrjoawxC.clone());
    }

    pub fn remove_host(&mut self, oGrFenSKoy: &nrRdtqRmYR) -> Option<IGGqPVcktO> {
        self.ozIUomtdwG.HufwaNcdTR.remove(oGrFenSKoy)
    }

    pub fn add_host_from(
        &mut self,
        irYnQdUWhH: &crate::scan::JSBnVRVdkm,
        TNWBTUVmdp: String,
        puUkMBApeA: Option<String>,
        XfiOfpdLRW: u16,
    ) -> anyhow::Result<()> {
        let kZbpscHDUK = IGGqPVcktO {
            ehmAIyyTsT: irYnQdUWhH.TLxIayDIUv,
            EUIBybvxzR: TNWBTUVmdp,
            RCEWxSXxDu: puUkMBApeA,
            XfiOfpdLRW,
            AtxPWiUcZC: irYnQdUWhH.EsDudBsHYo.clone(),
            VCeqAEcxUW: HashSet::new(),
            WpFxLZmBnAjyBPT: irYnQdUWhH.dciExZZqwj,
            aAoAoHiCrb: HashSet::new(),
        };
        self.ozIUomtdwG
            .HufwaNcdTR
            .insert(kZbpscHDUK.ehmAIyyTsT, kZbpscHDUK);
        Ok(())
    }

    pub fn hosts(&self) -> &HashMap<nrRdtqRmYR, IGGqPVcktO> {
        &self.ozIUomtdwG.HufwaNcdTR
    }

    pub fn script_hosts(&self) -> Box<dyn Iterator<Item = (&nrRdtqRmYR, &IGGqPVcktO)> + '_> {
        // Filter out hosts that don't have SSH open
        let GChiHYIosj = self
            .hosts()
            .iter()
            .filter(|(_, host)| host.AtxPWiUcZC.contains(&22));
        match self.get_cidr() {
            Some(wbPcGiTLXt) => Box::new(GChiHYIosj.filter(move |(FdBbuopFcL, _)| {
                // Get all the addresses that are not part of the excluded octets
                self.oqdaWrUSsH()
                    .iter()
                    .filter_map(|octet| {
                        let iekepJRXpb = Ipv4Addr::from_bits(*octet as u32);
                        convert_to_cidr(wbPcGiTLXt, iekepJRXpb.into()).ok()
                    })
                    .all(|kopykQhMGp| kopykQhMGp != **FdBbuopFcL)
            })),
            None => Box::new(GChiHYIosj),
        }
    }

    pub fn hosts_mut(&mut self) -> &mut HashMap<nrRdtqRmYR, IGGqPVcktO> {
        &mut self.ozIUomtdwG.HufwaNcdTR
    }

    pub fn WekoguFrXM(&self, filename: &Path) -> anyhow::Result<()> {
        let file = File::create(filename)?;
        let mut writer = BufWriter::new(file);
        for (_, host) in self.ozIUomtdwG.HufwaNcdTR.iter().filter(|(_, host)| {
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

    pub fn import_compat(&mut self, FanrWYxtoc: &Path) -> anyhow::Result<()> {
        let HLyoYlxtWb = File::open(FanrWYxtoc)?;
        let itWrVAjPGU = BufReader::new(HLyoYlxtWb);
        for wUdecUIFtG in itWrVAjPGU.lines().map_while(Result::ok) {
            let CzAHGdQfJK = wUdecUIFtG.split(" ").collect::<Vec<_>>();
            if CzAHGdQfJK.len() < 4 {
                anyhow::bail!("invalid line format in legacy file format");
            }
            let UPAikksqfq = CzAHGdQfJK[0].parse()?;
            let oNOpmqbhNK = CzAHGdQfJK[1].to_owned();
            let HdkSuZLDrU = CzAHGdQfJK[2].to_owned();
            let ATBNsINRid: u16 = CzAHGdQfJK[3].parse()?;
            let LzhuxEaLLI = CzAHGdQfJK[4..]
                .iter()
                .map(|alias| alias.to_string())
                .collect();
            let gHerdsWuoN = IGGqPVcktO {
                ehmAIyyTsT: UPAikksqfq,
                EUIBybvxzR: oNOpmqbhNK,
                RCEWxSXxDu: Some(HdkSuZLDrU),
                XfiOfpdLRW: ATBNsINRid,
                VCeqAEcxUW: LzhuxEaLLI,
                AtxPWiUcZC: HashSet::new(),
                WpFxLZmBnAjyBPT: ZmBnAjyBPT::UnixLike,
                aAoAoHiCrb: HashSet::new(),
            };
            self.add_host(&gHerdsWuoN);
        }
        Ok(())
    }

    pub fn get_long_timeout(&self) -> Duration {
        self.ozIUomtdwG.vizispDrXX
    }

    pub fn set_long_timeout(&mut self, tioMLegAem: Duration) {
        self.ozIUomtdwG.vizispDrXX = tioMLegAem;
    }

    pub fn get_short_timeout(&self) -> Duration {
        self.ozIUomtdwG.mEgnvlxemV
    }

    pub fn set_short_timeout(&mut self, OqSFxmGhEG: Duration) {
        self.ozIUomtdwG.mEgnvlxemV = OqSFxmGhEG;
    }

    pub fn linux_root(&self) -> &str {
        &self.ozIUomtdwG.YnfwmzWLem
    }
    pub fn windows_root(&self) -> &str {
        &self.ozIUomtdwG.pcfxYEXSfZ
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        let _ = self.save();
    }
}
