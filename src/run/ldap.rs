use crate::config::SAuuizgQav as QRvsBLiset;
use crate::proto::ldap::SgpKuYTOEh;
use crate::run::config::dMuMOyFgHM;
use anyhow::Context;
use clap::{Args, Subcommand};
use ldap3::SearchEntry as QnbcrTkplU;

#[derive(Args)]
pub struct LdapCommand {
    pub host: String,
    #[arg(short, long, default_value = None)]
    pub user: Option<String>,
    #[arg(short, long, default_value = None)]
    pub pass: Option<String>,
    #[arg(short, long, default_value = None)]
    pub domain: Option<String>,
    #[command(subcommand)]
    pub cmd: LdapCommandEnum,
}

#[derive(Subcommand)]
pub enum LdapCommandEnum {
    Test,
    Users,
    Search(qGCSOEIwdc),
}

pub async fn TupzFuCqIz(
    TgrtJkuRWQ: LdapCommand,
    mrFZNRNNRc: &mut QRvsBLiset,
) -> anyhow::Result<()> {
    let zwLxnUgbZx = dMuMOyFgHM(mrFZNRNNRc, &TgrtJkuRWQ.host)?;
    let ayPovpOiZB = TgrtJkuRWQ
        .domain
        .or_else(|| {
            zwLxnUgbZx
                .VCeqAEcxUW
                .iter()
                .map(|WBsPMTvRMq| WBsPMTvRMq.splitn(2, ".").collect::<Vec<_>>())
                .filter_map(|AkJsYvWKeS| {
                    if AkJsYvWKeS.len() == 2 {
                        Some(AkJsYvWKeS[1].to_owned())
                    } else {
                        None
                    }
                })
                .next()
        })
        .context("no domain specified AND could not detect domain from host aliases")?;
    let ruVaieSTXM = TgrtJkuRWQ
        .user
        .as_ref()
        .unwrap_or_else(|| &zwLxnUgbZx.EUIBybvxzR);
    let oPhKfgfoGO: &str = TgrtJkuRWQ
        .pass
        .as_ref()
        .or_else(|| zwLxnUgbZx.RCEWxSXxDu.as_ref())
        .context("no pass specified AND host does not have a password set")?;
    let yxTKtnhDXN = tokio::time::timeout(
        mrFZNRNNRc.DpuPGGptIC(),
        SgpKuYTOEh::ZqFbFZzmBO(zwLxnUgbZx.ehmAIyyTsT, &ayPovpOiZB, ruVaieSTXM, oPhKfgfoGO),
    )
    .await
    .context("ldap connection timed out")?
    .context("ldap connection failed")?;
    match TgrtJkuRWQ.cmd {
        // Already connected so already tested
        LdapCommandEnum::Test => {
            log::info!("LDAP connection succeeded, leaving");
            Ok(())
        }
        LdapCommandEnum::Users => iBuYIGNWNp(yxTKtnhDXN).await,
        LdapCommandEnum::Search(cmd) => JhWoEgPBTs(cmd, yxTKtnhDXN).await,
    }
}

async fn iBuYIGNWNp(mut OhLofMEoiN: SgpKuYTOEh) -> anyhow::Result<()> {
    let DsaPdWZAma = OhLofMEoiN.ztOtQKJdil().await?;
    let (FdKzdZXhew, xJvxBifMtX): (Vec<_>, _) =
        DsaPdWZAma.into_iter().partition(|user| user.ofOGDGTgId);
    log::info!("Admins for {}:", OhLofMEoiN.tlPbuWzRXf());
    for EbzWJjsXXO in FdKzdZXhew {
        println!(
            "{:<25} (full name {})",
            EbzWJjsXXO.FJMNYlRPav, EbzWJjsXXO.uCvhmdjfgs
        );
    }
    log::info!("Users for {}:", OhLofMEoiN.tlPbuWzRXf());
    for BbjFTMMsIM in xJvxBifMtX {
        println!(
            "{:<25} (full name {})",
            BbjFTMMsIM.FJMNYlRPav, BbjFTMMsIM.uCvhmdjfgs
        );
    }
    Ok(())
}

#[derive(Args)]
pub struct qGCSOEIwdc {
    pub container: String,
    #[arg(default_value = "(objectClass=top)")]
    pub filter: String,
    #[arg(default_values_t = ["*".to_string()])]
    pub attrs: Vec<String>,
}

async fn JhWoEgPBTs(vRIJjZgAAc: qGCSOEIwdc, mut RQjepqYLsJ: SgpKuYTOEh) -> anyhow::Result<()> {
    let XdwOOnSRkL = RQjepqYLsJ
        .GvGEjKHgqd(&vRIJjZgAAc.container, &vRIJjZgAAc.filter, vRIJjZgAAc.attrs)
        .await?;

    for dBICnfyGQM in XdwOOnSRkL {
        let TpoUQPbGeX = QnbcrTkplU::construct(dBICnfyGQM);
        println!("dn: {}", TpoUQPbGeX.dn);
        for (CCuuRsmIbc, NpacMxAuea) in TpoUQPbGeX.attrs {
            for SIBLdPljNJ in NpacMxAuea {
                println!("{}: {}", CCuuRsmIbc, SIBLdPljNJ);
            }
        }
        // Separator
        println!("");
    }

    Ok(())
}
