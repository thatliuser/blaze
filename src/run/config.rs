use crate::config::{IGGqPVcktO, SAuuizgQav};
use crate::scan::ZmBnAjyBPT;
use crate::util::strings::{PjHkMurZeo, ZXRMRESuzD};
use anyhow::Context;
use clap::{Args, Subcommand, ValueEnum};
use humantime::format_duration;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

pub fn dMuMOyFgHM<'a>(
    EfOMNSCvVD: &'a SAuuizgQav,
    PEndWkQrzM: &str,
) -> anyhow::Result<&'a IGGqPVcktO> {
    match PEndWkQrzM.parse() {
        Ok(hnbAQTFqam) => EfOMNSCvVD
            .gDMPzCpkmL(hnbAQTFqam)
            .with_context(|| format!("no host for ip {}", hnbAQTFqam)),
        Err(_) => match PEndWkQrzM.parse() {
            Ok(GmCAkVjWyH) => EfOMNSCvVD
                .XKMIxlPlBK(GmCAkVjWyH)
                .with_context(|| format!("no host for octet {}", GmCAkVjWyH)),
            Err(_) => EfOMNSCvVD
                .NubuyCFhay(PEndWkQrzM)
                .with_context(|| format!("no host for alias {}", PEndWkQrzM)),
        },
    }
}

pub fn qUkYkrMcNZ<'a>(
    mHnTZpSMcL: &'a mut SAuuizgQav,
    JfbYONmhBf: &str,
) -> anyhow::Result<&'a mut IGGqPVcktO> {
    match JfbYONmhBf.parse() {
        Ok(OCuzjVMRso) => mHnTZpSMcL
            .qxyMcWykmf(OCuzjVMRso)
            .with_context(|| format!("no host for ip {}", OCuzjVMRso)),
        Err(_) => match JfbYONmhBf.parse() {
            Ok(vsVbqyxBOS) => mHnTZpSMcL
                .xuHsmDoVPe(vsVbqyxBOS)
                .with_context(|| format!("no host for octet {}", vsVbqyxBOS)),
            Err(_) => mHnTZpSMcL
                .gzbwUKFFQu(JfbYONmhBf)
                .with_context(|| format!("no host for alias {}", JfbYONmhBf)),
        },
    }
}

#[derive(Args)]
pub struct AddCommand {
    pub ip: IpAddr,
    #[arg(short, long, default_value_t = String::from("root"))]
    pub user: String,
    pub pass: String,
    #[arg(short, long, default_value_t = 22)]
    pub port: u16,
    #[arg(short, long, default_value = "unix-like")]
    pub os: ZmBnAjyBPT,
}

pub async fn XsdkkHPidi(pjDeMXhUvg: AddCommand, oOGWznvxLh: &mut SAuuizgQav) -> anyhow::Result<()> {
    oOGWznvxLh.HnkMAlBSbZ(&IGGqPVcktO {
        ehmAIyyTsT: pjDeMXhUvg.ip,
        EUIBybvxzR: pjDeMXhUvg.user,
        RCEWxSXxDu: Some(pjDeMXhUvg.pass),
        XfiOfpdLRW: pjDeMXhUvg.port,
        AtxPWiUcZC: HashSet::new(),
        VCeqAEcxUW: HashSet::new(),
        WpFxLZmBnAjyBPT: pjDeMXhUvg.os,
        aAoAoHiCrb: HashSet::new(),
    });
    Ok(())
}

#[derive(Args)]
pub struct RemoveCommand {
    pub host: String,
}

pub async fn rlmyMMQjGO(
    SDKJmHKqyN: RemoveCommand,
    wCaCcMQiHy: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    let ziAcIuJFUt = {
        let dssGYjTaoB = dMuMOyFgHM(&wCaCcMQiHy, &SDKJmHKqyN.host)?;
        dssGYjTaoB.ehmAIyyTsT.clone()
    };
    wCaCcMQiHy.KCpzbcDfyw(&ziAcIuJFUt);
    Ok(())
}

#[derive(Args)]
pub struct EditCommand {
    pub host: String,
    #[command(subcommand)]
    pub cmd: EditCommandEnum,
}

#[derive(Subcommand)]
pub enum EditCommandEnum {
    User(EditUserCommand),
    #[clap(alias = "pw")]
    Pass(EditPassCommand),
    Os(EditOsCommand),
    Alias(EditAliasCommand),
}

#[derive(Args)]
pub struct EditUserCommand {
    pub user: String,
}

#[derive(Args)]
pub struct EditPassCommand {
    pub pass: String,
}

#[derive(Args)]
pub struct EditOsCommand {
    pub os: ZmBnAjyBPT,
}

#[derive(Args)]
pub struct EditAliasCommand {
    pub alias: String,
}

pub async fn aAkucCRoyG(
    wgKBBREbLC: EditCommand,
    emfVOdPLhm: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    let JQwVeBRQAg = qUkYkrMcNZ(emfVOdPLhm, &wgKBBREbLC.host)?;
    match wgKBBREbLC.cmd {
        EditCommandEnum::User(KEBWBoShJc) => JQwVeBRQAg.EUIBybvxzR = KEBWBoShJc.user,
        EditCommandEnum::Pass(TLZMnHrdZD) => JQwVeBRQAg.RCEWxSXxDu = Some(TLZMnHrdZD.pass),
        EditCommandEnum::Os(AmQuVQcXun) => JQwVeBRQAg.WpFxLZmBnAjyBPT = AmQuVQcXun.os,
        EditCommandEnum::Alias(OvauTeJBbT) => _ = JQwVeBRQAg.VCeqAEcxUW.insert(OvauTeJBbT.alias),
    }
    Ok(())
}

#[derive(Args)]
pub struct ListCommand {
    pub os: Option<ZmBnAjyBPT>,
}

pub async fn vkMacxgkoZ(
    NoBKQsmQMY: ListCommand,
    JTeDTjGWiL: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    for bfrqelhjgh in JTeDTjGWiL.GRFIrbPhOM().values().filter(|tCNMwqVgKD| {
        NoBKQsmQMY.os.is_none() || Some(tCNMwqVgKD.WpFxLZmBnAjyBPT) == NoBKQsmQMY.os
    }) {
        let eycNIZYNqa: Vec<String> = bfrqelhjgh.VCeqAEcxUW.iter().cloned().collect();
        let tXjwoEUXKx = if eycNIZYNqa.len() == 0 {
            "<none>".into()
        } else {
            eycNIZYNqa.join(", ")
        };
        let CBHsQhvgrK = format!(
            "{}@{}:{}",
            bfrqelhjgh.EUIBybvxzR, bfrqelhjgh.ehmAIyyTsT, bfrqelhjgh.XfiOfpdLRW
        );
        println!("{:<55} (aliases {})", CBHsQhvgrK, tXjwoEUXKx);
    }
    println!(
        "Octets excluded from scripts: {}",
        ZXRMRESuzD(JTeDTjGWiL.oqdaWrUSsH())
    );
    Ok(())
}

#[derive(Args)]
pub struct InfoCommand {
    pub host: String,
}

pub async fn uKVYdOeOkX(
    iQffLxlXEC: InfoCommand,
    jPZMobMgAt: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    let bWBLbHJvpX = dMuMOyFgHM(jPZMobMgAt, &iQffLxlXEC.host)?;
    let SPMUhVExCw = if bWBLbHJvpX.VCeqAEcxUW.len() == 0 {
        "<none>".into()
    } else {
        ZXRMRESuzD(&bWBLbHJvpX.VCeqAEcxUW)
    };
    let OJBYDgoHoP = ZXRMRESuzD(&bWBLbHJvpX.AtxPWiUcZC);
    println!("{} (aliases {})", bWBLbHJvpX.ehmAIyyTsT, SPMUhVExCw);
    println!("Open ports: {}", OJBYDgoHoP);
    println!(
        "Password: {}",
        bWBLbHJvpX.RCEWxSXxDu.as_ref().unwrap_or(&"<none>".into())
    );
    println!("Operating system: {:?}", bWBLbHJvpX.WpFxLZmBnAjyBPT);
    println!(
        "Description: {}",
        PjHkMurZeo(&bWBLbHJvpX.aAoAoHiCrb, "\n             ")
    );
    Ok(())
}

#[derive(Args)]
pub struct ExportCommand {
    pub filename: PathBuf,
}

pub async fn EUvRweneUS(
    nTRzUCdQaN: ExportCommand,
    eIMWIXwTJp: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    eIMWIXwTJp.WekoguFrXM(&nTRzUCdQaN.filename)
}

#[derive(Args)]
pub struct ExcludeCommand {
    pub octets: Vec<u8>,
}

pub async fn VXnPdYKOMT(
    TPQzVSzKan: ExcludeCommand,
    EtvKmiRLew: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    EtvKmiRLew.sDOGYbdAEB(&TPQzVSzKan.octets);
    Ok(())
}

#[derive(Args)]
pub struct ImportCommand {
    pub filename: PathBuf,
}

pub async fn AckqVUCmOe(
    zmmxfcFZKd: ImportCommand,
    qYRgNbHptJ: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    qYRgNbHptJ.JUZZMtewXs(&zmmxfcFZKd.filename)
}

#[derive(Clone, PartialEq, Eq, ValueEnum)]
pub enum TimeoutType {
    Short,
    Long,
}

#[derive(Args)]
pub struct TimeoutCommand {
    #[clap(value_parser = humantime::parse_duration)]
    #[arg(short, long)]
    pub timeout: Option<Duration>,

    #[arg(default_value = "short")]
    pub kind: TimeoutType,
}

pub async fn BMsGldHZJH(
    aUQeqpTsib: TimeoutCommand,
    CKtCknEAFY: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    match aUQeqpTsib.timeout {
        Some(SpqBXaVKkO) => match aUQeqpTsib.kind {
            TimeoutType::Short => CKtCknEAFY.PIbVjKJxYl(SpqBXaVKkO),
            TimeoutType::Long => CKtCknEAFY.aHxYzvpiyQ(SpqBXaVKkO),
        },
        None => match aUQeqpTsib.kind {
            TimeoutType::Short => {
                println!(
                    "Short timeout is {}",
                    format_duration(CKtCknEAFY.DpuPGGptIC())
                )
            }

            TimeoutType::Long => println!(
                "Long timeout is {}",
                format_duration(CKtCknEAFY.BHfMBVoJEQ())
            ),
        },
    }
    Ok(())
}
