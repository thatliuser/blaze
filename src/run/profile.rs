use crate::config::{IGGqPVcktO, SAuuizgQav};
use crate::proto::{ldap::SgpKuYTOEh as LdapSession, rdp, ssh::yiqafanmjb as SshSession};
use crate::run::script::{run_script_all, RunScriptArgs};
use crate::scan::ZmBnAjyBPT;
use crate::util::ip::CrchwJMsNc as OXdmvYQuUy;
use anyhow::Context;
use cidr::IpCidr as LcqOtrfUKI;
use clap::{Args, ValueEnum};
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver as ezcSaHgATl;
use std::collections::HashSet as hVTcIFVhgo;
use std::path::PathBuf;
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(ValueEnum, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum VIaDosyWNk {
    // Ordered by what should be checked first
    Rdp,
    Ssh,
    Hostname,
    Ldap,
}

#[derive(Args)]
#[command(
    about = "Profile computers on the network with various protocols. If no strategies are set, it will run all of them."
)]
pub struct ProfileCommand {
    pub strategies: Option<Vec<VIaDosyWNk>>,
}

pub async fn XAzfUKbpUB(
    ZXZjUGYVXL: ProfileCommand,
    GnNwsTxgjv: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    let mut uEnyMKibhn = ZXZjUGYVXL.strategies.unwrap_or_else(|| {
        log::info!("No strategy picked, setting all");
        vec![
            VIaDosyWNk::Rdp,
            VIaDosyWNk::Ssh,
            VIaDosyWNk::Hostname,
            VIaDosyWNk::Ldap,
        ]
    });
    // Sort so that strategies are in order
    uEnyMKibhn.sort();
    // let set = JoinSet::new()
    for VlsGFLHzMc in uEnyMKibhn {
        match VlsGFLHzMc {
            VIaDosyWNk::Rdp => KbmRaYlTbY(GnNwsTxgjv).await?,
            VIaDosyWNk::Ssh => lgcRRfVmcQ(GnNwsTxgjv).await?,
            VIaDosyWNk::Hostname => YMzayfRIUI(GnNwsTxgjv).await?,
            VIaDosyWNk::Ldap => uAfuAyQMFM(GnNwsTxgjv).await?,
        }
    }
    Ok(())
}

pub async fn KbmRaYlTbY(fiVAYjtXQD: &mut SAuuizgQav) -> anyhow::Result<()> {
    let lEtrHSmzBc = fiVAYjtXQD.get_short_timeout();
    let mut BTuFRygfzN = JoinSet::new();
    for (_, MLVdWODNRT) in fiVAYjtXQD
        .GRFIrbPhOM()
        .iter()
        .filter(|(_, AxLEVVfhHI)| AxLEVVfhHI.AtxPWiUcZC.contains(&3389))
    {
        let sVOVWyVGia = MLVdWODNRT.clone();
        BTuFRygfzN.spawn(async move {
            (
                sVOVWyVGia.clone(),
                rdp::grab_rdp_hostname(sVOVWyVGia.ehmAIyyTsT, lEtrHSmzBc).await,
            )
        });
    }
    while let Some(oVbQYUVgeg) = BTuFRygfzN.join_next().await {
        let (mut tsfbNYcmXQ, AGOaNHWRVl) = oVbQYUVgeg.context("Error running rdp command")?;
        match AGOaNHWRVl {
            Ok(NuZCHmXRzB) => {
                log::info!("Got name {} for host {}", NuZCHmXRzB, tsfbNYcmXQ);
                tsfbNYcmXQ.VCeqAEcxUW.insert(NuZCHmXRzB);
                fiVAYjtXQD.HnkMAlBSbZ(&tsfbNYcmXQ);
            }
            Err(FbHAXQxDvM) => {
                log::error!(
                    "Failed to get rdp hostname for host {}: {}",
                    tsfbNYcmXQ,
                    FbHAXQxDvM
                );
            }
        }
    }
    Ok(())
}

pub async fn ACvtzPOmfG(
    host: &IGGqPVcktO,
    timeout: Duration,
) -> anyhow::Result<(String, ZmBnAjyBPT)> {
    let ExCiITyPyC = SshSession::NiyIrattFM((host.ehmAIyyTsT, host.XfiOfpdLRW), timeout).await?;
    let dnVnEUdtIZ = if ExCiITyPyC.to_lowercase().contains("windows") {
        ZmBnAjyBPT::Windows
    } else {
        ZmBnAjyBPT::UnixLike
    };
    Ok((ExCiITyPyC, dnVnEUdtIZ))
}

pub async fn lgcRRfVmcQ(QEInBbRyrJ: &mut SAuuizgQav) -> anyhow::Result<()> {
    let mut wrGLqRuaNw = JoinSet::new();
    for (_, GCxYtLbPXV) in QEInBbRyrJ.GRFIrbPhOM() {
        let kPGLFhJnHg = GCxYtLbPXV.clone();
        let fEmyREnAOK = QEInBbRyrJ.get_short_timeout();
        wrGLqRuaNw.spawn(async move {
            (
                kPGLFhJnHg.clone(),
                ACvtzPOmfG(&kPGLFhJnHg, fEmyREnAOK).await,
            )
        });
    }
    while let Some(xEWIzwNNra) = wrGLqRuaNw.join_next().await {
        let (mut DQOcFiPxCH, cJPRKPQnZn) =
            xEWIzwNNra.context("Failed to spawn host ID detector")?;
        match cJPRKPQnZn {
            Ok((fbSCncVcTs, LfgXNjVwak)) => {
                log::info!("Got ssh ID {} for host {}", fbSCncVcTs.trim(), DQOcFiPxCH);
                DQOcFiPxCH.aAoAoHiCrb.insert(fbSCncVcTs.trim().to_string());
                match LfgXNjVwak {
                    ZmBnAjyBPT::UnixLike => {
                        DQOcFiPxCH.WpFxLZmBnAjyBPT = ZmBnAjyBPT::UnixLike;
                        DQOcFiPxCH.EUIBybvxzR = QEInBbRyrJ.linux_root().into();
                    }
                    ZmBnAjyBPT::Windows => {
                        DQOcFiPxCH.WpFxLZmBnAjyBPT = ZmBnAjyBPT::Windows;
                        DQOcFiPxCH.EUIBybvxzR = QEInBbRyrJ.windows_root().into();
                    }
                }
                if LfgXNjVwak != DQOcFiPxCH.WpFxLZmBnAjyBPT {
                    DQOcFiPxCH.WpFxLZmBnAjyBPT = LfgXNjVwak;
                }
                QEInBbRyrJ.HnkMAlBSbZ(&DQOcFiPxCH);
            }
            Err(dSFtXdnVFY) => {
                log::error!(
                    "Failed to detect ssh ID for host {}: {}",
                    DQOcFiPxCH,
                    dSFtXdnVFY
                );
            }
        }
    }
    Ok(())
}

pub async fn YMzayfRIUI(vKCcRrnoZL: &mut SAuuizgQav) -> anyhow::Result<()> {
    let McaOMhxbcw = PathBuf::from("hostname.sh");
    let mut XMNllzSMwV =
        // SSH is slow so give it some more time
        run_script_all(vKCcRrnoZL.get_short_timeout().max(Duration::from_secs(2)), vKCcRrnoZL, RunScriptArgs::new(McaOMhxbcw)).await;
    while let Some(bHHHoZysIi) = XMNllzSMwV.join_next().await {
        let (mut aIGIXjYZFW, DBmnrkfjky) = bHHHoZysIi.context("Error running hostname script")?;
        match DBmnrkfjky {
            Ok((urDUagBWen, anoAYwHDYu)) => {
                log::warn!(
                    "Hostname script returned nonzero code {} for host {}",
                    urDUagBWen,
                    aIGIXjYZFW
                );
                let EvBbHeblpH = anoAYwHDYu.trim();
                log::info!("Got alias {} for host {}", EvBbHeblpH, aIGIXjYZFW);
                aIGIXjYZFW.VCeqAEcxUW.insert(EvBbHeblpH.into());
                vKCcRrnoZL.HnkMAlBSbZ(&aIGIXjYZFW);
            }
            Err(XMkwuQEXFp) => {
                log::error!(
                    "Error running script on host {}: {}",
                    aIGIXjYZFW,
                    XMkwuQEXFp
                );
            }
        }
    }
    Ok(())
}

// Collect all aliases of all hosts, then find only the ones
// that are of the form "<name>.<domainpart>.<domainpart>..."
fn ypjgWDuvYs(GNchTXIpHr: &SAuuizgQav) -> hVTcIFVhgo<String> {
    GNchTXIpHr
        .GRFIrbPhOM()
        .iter()
        .flat_map(|(_, tlnCKjgPmg)| {
            tlnCKjgPmg
                .VCeqAEcxUW
                .iter()
                .map(|XzOXYaGyEv| XzOXYaGyEv.splitn(2, '.').collect::<Vec<_>>())
        })
        .filter_map(|tXkzEjyjCP| {
            if tXkzEjyjCP.len() == 2 {
                Some(tXkzEjyjCP[1].to_owned())
            } else {
                None
            }
        })
        .collect()
}

// See if the DNS server is associated with a domain.
async fn nApXytTlCs<'a>(
    lCUpIZPfFj: &IGGqPVcktO,
    tDeTGfMeia: &ezcSaHgATl,
    xellGGmrWB: &'a hVTcIFVhgo<String>,
    WWDJWxKhST: &LcqOtrfUKI,
) -> Option<&'a str> {
    for SRytBffxDz in xellGGmrWB {
        // TODO: JoinSet
        let OcBoDZYOcL = tDeTGfMeia.lookup_ip(SRytBffxDz).await;
        // Look through the list of ips returned and see if any match the current host.
        // If they do, return the domain.
        let PFyczyICWc = OcBoDZYOcL
            .map(|UUNdyUntoM| {
                UUNdyUntoM
                    .iter()
                    .filter_map(|QwsqLsWwrd| OXdmvYQuUy(*WWDJWxKhST, QwsqLsWwrd).ok())
                    .filter(|LVDkErDHue| LVDkErDHue == &lCUpIZPfFj.ehmAIyyTsT)
                    .next()
            })
            .ok()
            .flatten();
        if PFyczyICWc.is_some() {
            return Some(SRytBffxDz.as_str());
        }
    }
    None
}

async fn ZVmEZkuOlw(
    TUFCUEtrUx: &IGGqPVcktO,
    lrhvgiNwYI: &str,
    GVofmsLViF: LcqOtrfUKI,
    gaqbSJgxXt: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    if let Some(eIAEUscbdU) = &TUFCUEtrUx.RCEWxSXxDu {
        let mut UKOPexzmOw = TUFCUEtrUx.clone();
        UKOPexzmOw
            .aAoAoHiCrb
            .insert(format!("Domain controller for {}", lrhvgiNwYI));
        gaqbSJgxXt.HnkMAlBSbZ(&UKOPexzmOw);
        let mHhDOeTgkY = gaqbSJgxXt.get_short_timeout();
        let mut iaFMOAbNZT = tokio::time::timeout(
            mHhDOeTgkY,
            LdapSession::ZqFbFZzmBO(
                UKOPexzmOw.ehmAIyyTsT,
                lrhvgiNwYI,
                &UKOPexzmOw.EUIBybvxzR,
                eIAEUscbdU,
            ),
        )
        .await
        .context("ldap connection timed out")?
        .context("error connecting to ldap")?;
        let mut yvBGDVynzf = ResolverConfig::new();
        yvBGDVynzf.add_name_server(NameServerConfig::new(
            (UKOPexzmOw.ehmAIyyTsT, 53).into(),
            Protocol::Tcp,
        ));
        yvBGDVynzf.set_domain(
            format!("{}.", lrhvgiNwYI)
                .parse()
                .context("domain has invalid format for DNS resolver")?,
        );
        // Create new DNS server with domain as search domain
        let mut OyCsLeflAU = ResolverOpts::default();
        OyCsLeflAU.timeout = mHhDOeTgkY;
        OyCsLeflAU.attempts = 2;
        let iNXbbDQMuN = ezcSaHgATl::tokio(yvBGDVynzf, OyCsLeflAU);
        for plkMIYWVCf in iaFMOAbNZT.mrYxCAWUem().await? {
            // Either the name without the domain as a suffix, or just the name if it doesn't contain the suffix
            let PoxeTfHoFK = iNXbbDQMuN
                .lookup_ip(plkMIYWVCf.vMoYcEINHf.clone())
                .await
                .ok()
                .and_then(|FYRQoXZymU| FYRQoXZymU.iter().next())
                .and_then(|LLHXzlSvKk| {
                    log::info!("Computer {} has ip {}", plkMIYWVCf.YoMZFBEXti, LLHXzlSvKk);
                    OXdmvYQuUy(GVofmsLViF, LLHXzlSvKk).ok()
                })
                .and_then(|NjwAxvJLsz| gaqbSJgxXt.gDMPzCpkmL(NjwAxvJLsz));
            match PoxeTfHoFK {
                Some(fOkuNhzWKe) => {
                    let mut JSGrptPDwf = fOkuNhzWKe.clone();
                    JSGrptPDwf.VCeqAEcxUW.insert(plkMIYWVCf.YoMZFBEXti);
                    JSGrptPDwf.VCeqAEcxUW.insert(plkMIYWVCf.vMoYcEINHf);
                    if let Some(EqpGhusqXt) = plkMIYWVCf.RkTmGzJZwW {
                        log::info!("Host {} has OS {}", JSGrptPDwf, EqpGhusqXt);
                        if EqpGhusqXt.to_lowercase().contains("windows") {
                            JSGrptPDwf.WpFxLZmBnAjyBPT = ZmBnAjyBPT::Windows;
                            JSGrptPDwf.EUIBybvxzR = gaqbSJgxXt.windows_root().into();
                        } else if EqpGhusqXt.to_lowercase().contains("linux") {
                            JSGrptPDwf.WpFxLZmBnAjyBPT = ZmBnAjyBPT::UnixLike;
                            JSGrptPDwf.EUIBybvxzR = gaqbSJgxXt.linux_root().into();
                        }
                        JSGrptPDwf.aAoAoHiCrb.insert(
                            format!(
                                "{} {}",
                                EqpGhusqXt,
                                plkMIYWVCf.vShGbXshZt.unwrap_or("".into())
                            )
                            .trim()
                            .to_string(),
                        );
                    }
                    gaqbSJgxXt.HnkMAlBSbZ(&JSGrptPDwf);
                }
                None => log::warn!(
                    "No host found for hostname {} in domain",
                    plkMIYWVCf.YoMZFBEXti
                ),
            }
        }
        Ok(())
    } else {
        anyhow::bail!(
            "Detected domain for DC {}, but no password!",
            TUFCUEtrUx.ehmAIyyTsT
        );
    }
}

pub async fn uAfuAyQMFM(Ynjqxsriwd: &mut SAuuizgQav) -> anyhow::Result<()> {
    let mapKZbYbqL = Ynjqxsriwd
        .sElCDVdLmF()
        .context("no cidr set; have you run a scan?")?;
    let PxwagZDSwR = ypjgWDuvYs(Ynjqxsriwd);
    log::info!("Found domains {:?}", PxwagZDSwR);
    // Find all the DNS servers we've found and create a resolver for them
    let LtWknvvBph: Vec<_> = Ynjqxsriwd
        .GRFIrbPhOM()
        .iter()
        .filter(|(_, AWxGHTKhpR)| AWxGHTKhpR.AtxPWiUcZC.contains(&53))
        .map(|(_, sEXgILeXxu)| {
            log::debug!("Adding DNS server {}", sEXgILeXxu);
            let mut jPqDsKBgtq = ResolverConfig::new();
            jPqDsKBgtq.add_name_server(NameServerConfig::new(
                (sEXgILeXxu.ehmAIyyTsT.clone(), 53).into(),
                Protocol::Tcp,
            ));
            (
                sEXgILeXxu.clone(),
                ezcSaHgATl::tokio(jPqDsKBgtq, Default::default()),
            )
        })
        .collect();
    let XQCfbitbUX = Ynjqxsriwd.get_short_timeout();
    for (WpSVcgwnNm, MAhMqoIiax) in LtWknvvBph {
        match tokio::time::timeout(
            XQCfbitbUX,
            nApXytTlCs(&WpSVcgwnNm, &MAhMqoIiax, &PxwagZDSwR, &mapKZbYbqL),
        )
        .await
        {
            Ok(JBEpgSkrHc) => match JBEpgSkrHc {
                Some(DebzBiINAy) => {
                    log::info!("Found domain {} for host {}", DebzBiINAy, WpSVcgwnNm);
                    if let Err(eUorZUyKnK) =
                        ZVmEZkuOlw(&WpSVcgwnNm, DebzBiINAy, mapKZbYbqL, Ynjqxsriwd).await
                    {
                        log::warn!(
                            "Error while running LDAP for DC {}: {}",
                            WpSVcgwnNm,
                            eUorZUyKnK
                        );
                    }
                }
                None => log::debug!("No domain matched for DNS server {}", WpSVcgwnNm),
            },
            Err(_) => log::debug!("DNS connection timed out for host {}", WpSVcgwnNm),
        }
    }
    Ok(())
}
