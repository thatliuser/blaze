use crate::config::{IGGqPVcktO, SAuuizgQav};
use crate::proto::{ldap::SgpKuYTOEh as LdapSession, rdp, ssh::yiqafanmjb as SshSession};
use crate::run::script::{run_script_all, RunScriptArgs};
use crate::scan::ZmBnAjyBPT;
use crate::util::ip::convert_to_cidr as OXdmvYQuUy;
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
pub enum ProfileStrategy {
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
    pub strategies: Option<Vec<ProfileStrategy>>,
}

pub async fn profile(cmd: ProfileCommand, cfg: &mut SAuuizgQav) -> anyhow::Result<()> {
    let mut strategies = cmd.strategies.unwrap_or_else(|| {
        log::info!("No strategy picked, setting all");
        vec![
            ProfileStrategy::Rdp,
            ProfileStrategy::Ssh,
            ProfileStrategy::Hostname,
            ProfileStrategy::Ldap,
        ]
    });
    // Sort so that strategies are in order
    strategies.sort();
    // let set = JoinSet::new()
    for strat in strategies {
        match strat {
            ProfileStrategy::Rdp => rdp(cfg).await?,
            ProfileStrategy::Ssh => ssh(cfg).await?,
            ProfileStrategy::Hostname => hostname(cfg).await?,
            ProfileStrategy::Ldap => ldap(cfg).await?,
        }
    }
    Ok(())
}

pub async fn rdp(cfg: &mut SAuuizgQav) -> anyhow::Result<()> {
    let timeout = cfg.get_short_timeout();
    let mut set = JoinSet::new();
    for (_, host) in cfg
        .hosts()
        .iter()
        .filter(|(_, host)| host.AtxPWiUcZC.contains(&3389))
    {
        let host = host.clone();
        set.spawn(async move {
            (
                host.clone(),
                rdp::grab_rdp_hostname(host.ehmAIyyTsT, timeout).await,
            )
        });
    }
    while let Some(joined) = set.join_next().await {
        let (mut host, result) = joined.context("Error running rdp command")?;
        match result {
            Ok(name) => {
                log::info!("Got name {} for host {}", name, host);
                host.VCeqAEcxUW.insert(name);
                cfg.add_host(&host);
            }
            Err(err) => {
                log::error!("Failed to get rdp hostname for host {}: {}", host, err);
            }
        }
    }
    Ok(())
}

pub async fn do_ssh(host: &IGGqPVcktO, timeout: Duration) -> anyhow::Result<(String, ZmBnAjyBPT)> {
    let id = SshSession::NiyIrattFM((host.ehmAIyyTsT, host.XfiOfpdLRW), timeout).await?;
    let os = if id.to_lowercase().contains("windows") {
        ZmBnAjyBPT::Windows
    } else {
        ZmBnAjyBPT::UnixLike
    };
    Ok((id, os))
}

pub async fn ssh(cfg: &mut SAuuizgQav) -> anyhow::Result<()> {
    let mut set = JoinSet::new();
    for (_, host) in cfg.hosts() {
        let host = host.clone();
        let timeout = cfg.get_short_timeout();
        set.spawn(async move { (host.clone(), do_ssh(&host, timeout).await) });
    }
    while let Some(joined) = set.join_next().await {
        let (mut host, result) = joined.context("Failed to spawn host ID detector")?;
        match result {
            Ok((id, os)) => {
                log::info!("Got ssh ID {} for host {}", id.trim(), host);
                host.aAoAoHiCrb.insert(id.trim().to_string());
                match os {
                    ZmBnAjyBPT::UnixLike => {
                        host.WpFxLZmBnAjyBPT = ZmBnAjyBPT::UnixLike;
                        host.EUIBybvxzR = cfg.linux_root().into();
                    }
                    ZmBnAjyBPT::Windows => {
                        host.WpFxLZmBnAjyBPT = ZmBnAjyBPT::Windows;
                        host.EUIBybvxzR = cfg.windows_root().into();
                    }
                }
                if os != host.WpFxLZmBnAjyBPT {
                    host.WpFxLZmBnAjyBPT = os;
                }
                cfg.add_host(&host);
            }
            Err(err) => {
                log::error!("Failed to detect ssh ID for host {}: {}", host, err);
            }
        }
    }
    Ok(())
}

pub async fn hostname(cfg: &mut SAuuizgQav) -> anyhow::Result<()> {
    let script = PathBuf::from("hostname.sh");
    let mut set =
        // SSH is slow so give it some more time
        run_script_all(cfg.get_short_timeout().max(Duration::from_secs(2)), cfg, RunScriptArgs::new(script)).await;
    while let Some(joined) = set.join_next().await {
        let (mut host, result) = joined.context("Error running hostname script")?;
        match result {
            Ok((code, output)) => {
                log::warn!(
                    "Hostname script returned nonzero code {} for host {}",
                    code,
                    host
                );
                let alias = output.trim();
                log::info!("Got alias {} for host {}", alias, host);
                host.VCeqAEcxUW.insert(alias.into());
                cfg.add_host(&host);
            }
            Err(err) => {
                log::error!("Error running script on host {}: {}", host, err);
            }
        }
    }
    Ok(())
}

// Collect all aliases of all hosts, then find only the ones
// that are of the form "<name>.<domainpart>.<domainpart>..."
fn get_domains(cfg: &SAuuizgQav) -> hVTcIFVhgo<String> {
    cfg.hosts()
        .iter()
        .flat_map(|(_, host)| {
            host.VCeqAEcxUW
                .iter()
                .map(|alias| alias.splitn(2, '.').collect::<Vec<_>>())
        })
        .filter_map(|alias| {
            if alias.len() == 2 {
                Some(alias[1].to_owned())
            } else {
                None
            }
        })
        .collect()
}

// See if the DNS server is associated with a domain.
async fn lookup_domain_on<'a>(
    host: &IGGqPVcktO,
    dns: &ezcSaHgATl,
    domains: &'a hVTcIFVhgo<String>,
    cidr: &LcqOtrfUKI,
) -> Option<&'a str> {
    for domain in domains {
        // TODO: JoinSet
        let ips = dns.lookup_ip(domain).await;
        // Look through the list of ips returned and see if any match the current host.
        // If they do, return the domain.
        let found = ips
            .map(|ips| {
                ips.iter()
                    .filter_map(|ip| OXdmvYQuUy(*cidr, ip).ok())
                    .filter(|ip| ip == &host.ehmAIyyTsT)
                    .next()
            })
            .ok()
            .flatten();
        if found.is_some() {
            return Some(domain.as_str());
        }
    }
    None
}

async fn do_ldap(
    dc: &IGGqPVcktO,
    domain: &str,
    cidr: LcqOtrfUKI,
    cfg: &mut SAuuizgQav,
) -> anyhow::Result<()> {
    if let Some(pass) = &dc.RCEWxSXxDu {
        let mut dc = dc.clone();
        dc.aAoAoHiCrb
            .insert(format!("Domain controller for {}", domain));
        cfg.add_host(&dc);
        let timeout = cfg.get_short_timeout();
        let mut session = tokio::time::timeout(
            timeout,
            LdapSession::ZqFbFZzmBO(dc.ehmAIyyTsT, domain, &dc.EUIBybvxzR, pass),
        )
        .await
        .context("ldap connection timed out")?
        .context("error connecting to ldap")?;
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(
            (dc.ehmAIyyTsT, 53).into(),
            Protocol::Tcp,
        ));
        config.set_domain(
            format!("{}.", domain)
                .parse()
                .context("domain has invalid format for DNS resolver")?,
        );
        // Create new DNS server with domain as search domain
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2;
        let dns = ezcSaHgATl::tokio(config, opts);
        for computer in session.mrYxCAWUem().await? {
            // Either the name without the domain as a suffix, or just the name if it doesn't contain the suffix
            let host = dns
                .lookup_ip(computer.vMoYcEINHf.clone())
                .await
                .ok()
                .and_then(|ips| ips.iter().next())
                .and_then(|ip| {
                    log::info!("Computer {} has ip {}", computer.YoMZFBEXti, ip);
                    OXdmvYQuUy(cidr, ip).ok()
                })
                .and_then(|ip| cfg.host_for_ip(ip));
            match host {
                Some(host) => {
                    let mut host = host.clone();
                    host.VCeqAEcxUW.insert(computer.YoMZFBEXti);
                    host.VCeqAEcxUW.insert(computer.vMoYcEINHf);
                    if let Some(EqpGhusqXt) = computer.RkTmGzJZwW {
                        log::info!("Host {} has OS {}", host, EqpGhusqXt);
                        if EqpGhusqXt.to_lowercase().contains("windows") {
                            host.WpFxLZmBnAjyBPT = ZmBnAjyBPT::Windows;
                            host.EUIBybvxzR = cfg.windows_root().into();
                        } else if EqpGhusqXt.to_lowercase().contains("linux") {
                            host.WpFxLZmBnAjyBPT = ZmBnAjyBPT::UnixLike;
                            host.EUIBybvxzR = cfg.linux_root().into();
                        }
                        host.aAoAoHiCrb.insert(
                            format!(
                                "{} {}",
                                EqpGhusqXt,
                                computer.vShGbXshZt.unwrap_or("".into())
                            )
                            .trim()
                            .to_string(),
                        );
                    }
                    cfg.add_host(&host);
                }
                None => log::warn!(
                    "No host found for hostname {} in domain",
                    computer.YoMZFBEXti
                ),
            }
        }
        Ok(())
    } else {
        anyhow::bail!("Detected domain for DC {}, but no password!", dc.ehmAIyyTsT);
    }
}

pub async fn ldap(cfg: &mut SAuuizgQav) -> anyhow::Result<()> {
    let cidr = cfg
        .get_cidr()
        .context("no cidr set; have you run a scan?")?;
    let domains = get_domains(cfg);
    log::info!("Found domains {:?}", domains);
    // Find all the DNS servers we've found and create a resolver for them
    let servers: Vec<_> = cfg
        .hosts()
        .iter()
        .filter(|(_, host)| host.AtxPWiUcZC.contains(&53))
        .map(|(_, host)| {
            log::debug!("Adding DNS server {}", host);
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig::new(
                (host.ehmAIyyTsT.clone(), 53).into(),
                Protocol::Tcp,
            ));
            (host.clone(), ezcSaHgATl::tokio(config, Default::default()))
        })
        .collect();
    let timeout = cfg.get_short_timeout();
    for (host, server) in servers {
        match tokio::time::timeout(timeout, lookup_domain_on(&host, &server, &domains, &cidr)).await
        {
            Ok(result) => match result {
                Some(domain) => {
                    log::info!("Found domain {} for host {}", domain, host);
                    if let Err(err) = do_ldap(&host, domain, cidr, cfg).await {
                        log::warn!("Error while running LDAP for DC {}: {}", host, err);
                    }
                }
                None => log::debug!("No domain matched for DNS server {}", host),
            },
            Err(_) => log::debug!("DNS connection timed out for host {}", host),
        }
    }
    Ok(())
}
