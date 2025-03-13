use crate::config::{Config, Host};
use crate::proto::{ldap::Session as LdapSession, rdp, ssh::Session as SshSession};
use crate::run::script::{run_script_all, RunScriptArgs};
use crate::scan::OsType;
use crate::util::ip::convert_to_cidr;
use anyhow::Context;
use cidr::IpCidr;
use clap::{Args, ValueEnum};
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashSet;
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

pub async fn profile(cmd: ProfileCommand, cfg: &mut Config) -> anyhow::Result<()> {
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

pub async fn rdp(cfg: &mut Config) -> anyhow::Result<()> {
    let timeout = cfg.get_short_timeout();
    let mut set = JoinSet::new();
    for (_, host) in cfg
        .hosts()
        .iter()
        .filter(|(_, host)| host.open_ports.contains(&3389))
    {
        let host = host.clone();
        set.spawn(async move { (host.clone(), rdp::grab_rdp_hostname(host.ip, timeout).await) });
    }
    while let Some(joined) = set.join_next().await {
        let (mut host, result) = joined.context("Error running rdp command")?;
        match result {
            Ok(name) => {
                log::info!("Got name {} for host {}", name, host);
                host.aliases.insert(name);
                cfg.add_host(&host);
            }
            Err(err) => {
                log::error!("Failed to get rdp hostname for host {}: {}", host, err);
            }
        }
    }
    Ok(())
}

pub async fn do_ssh(host: &Host, timeout: Duration) -> anyhow::Result<(String, OsType)> {
    let id = SshSession::get_server_id((host.ip, host.port), timeout).await?;
    let os = if id.to_lowercase().contains("windows") {
        OsType::Windows
    } else {
        OsType::UnixLike
    };
    Ok((id, os))
}

pub async fn ssh(cfg: &mut Config) -> anyhow::Result<()> {
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
                host.desc.insert(id.trim().to_string());
                match os {
                    OsType::UnixLike => {
                        host.os = OsType::UnixLike;
                        host.user = cfg.linux_root().into();
                    }
                    OsType::Windows => {
                        host.os = OsType::Windows;
                        host.user = cfg.windows_root().into();
                    }
                }
                if os != host.os {
                    host.os = os;
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

pub async fn hostname(cfg: &mut Config) -> anyhow::Result<()> {
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
                host.aliases.insert(alias.into());
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
fn get_domains(cfg: &Config) -> HashSet<String> {
    cfg.hosts()
        .iter()
        .flat_map(|(_, host)| {
            host.aliases
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
    host: &Host,
    dns: &TokioAsyncResolver,
    domains: &'a HashSet<String>,
    cidrs: &HashSet<IpCidr>,
) -> Option<(&'a str, IpCidr)> {
    for domain in domains {
        // TODO: JoinSet
        let ips = dns.lookup_ip(domain).await;
        // Look through the list of ips returned and see if any match the current host.
        // If they do, return the domain.
        let found = ips
            .map(|ips| {
                ips.iter()
                    .flat_map(|ip| {
                        cidrs.iter().filter_map(move |cidr| {
                            let ip = convert_to_cidr(*cidr, ip).ok()?;
                            Some((ip, cidr))
                        })
                    })
                    .filter(|(ip, _)| ip == &host.ip)
                    .next()
            })
            .ok()
            .flatten();
        match found {
            Some((_, cidr)) => {
                return Some((domain.as_str(), cidr.clone()));
            }
            _ => {}
        }
        if found.is_some() {}
    }
    None
}

async fn do_ldap(dc: &Host, domain: &str, cidr: &IpCidr, cfg: &mut Config) -> anyhow::Result<()> {
    if let Some(pass) = &dc.pass {
        let mut dc = dc.clone();
        dc.desc.insert(format!("Domain controller for {}", domain));
        cfg.add_host(&dc);
        let timeout = cfg.get_short_timeout();
        let mut session =
            tokio::time::timeout(timeout, LdapSession::new(dc.ip, domain, &dc.user, pass))
                .await
                .context("ldap connection timed out")?
                .context("error connecting to ldap")?;
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new((dc.ip, 53).into(), Protocol::Tcp));
        config.set_domain(
            format!("{}.", domain)
                .parse()
                .context("domain has invalid format for DNS resolver")?,
        );
        // Create new DNS server with domain as search domain
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2;
        let dns = TokioAsyncResolver::tokio(config, opts);
        for computer in session.computers().await? {
            // Either the name without the domain as a suffix, or just the name if it doesn't contain the suffix
            let host = dns
                .lookup_ip(computer.dns_name.clone())
                .await
                .ok()
                .and_then(|ips| ips.iter().next())
                .and_then(|ip| {
                    log::info!("Computer {} has ip {}", computer.name, ip);
                    convert_to_cidr(*cidr, ip).ok()
                })
                .and_then(|ip| cfg.host_for_ip(ip));
            match host {
                Some(host) => {
                    let mut host = host.clone();
                    host.aliases.insert(computer.name);
                    host.aliases.insert(computer.dns_name);
                    if let Some(os) = computer.os {
                        log::info!("Host {} has OS {}", host, os);
                        if os.to_lowercase().contains("windows") {
                            host.os = OsType::Windows;
                            host.user = cfg.windows_root().into();
                        } else if os.to_lowercase().contains("linux") {
                            host.os = OsType::UnixLike;
                            host.user = cfg.linux_root().into();
                        }
                        host.desc.insert(
                            format!("{} {}", os, computer.os_version.unwrap_or("".into()))
                                .trim()
                                .to_string(),
                        );
                    }
                    cfg.add_host(&host);
                }
                None => log::warn!("No host found for hostname {} in domain", computer.name),
            }
        }
        Ok(())
    } else {
        anyhow::bail!("Detected domain for DC {}, but no password!", dc.ip);
    }
}

pub async fn ldap(cfg: &mut Config) -> anyhow::Result<()> {
    let cidrs = cfg.get_cidrs().clone();
    if cidrs.len() == 0 {
        anyhow::bail!("no cidr set; have you run a scan?");
    }
    let domains = get_domains(cfg);
    log::info!("Found domains {:?}", domains);
    // Find all the DNS servers we've found and create a resolver for them
    let servers: Vec<_> = cfg
        .hosts()
        .iter()
        .filter(|(_, host)| host.open_ports.contains(&53))
        .map(|(_, host)| {
            log::debug!("Adding DNS server {}", host);
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig::new(
                (host.ip.clone(), 53).into(),
                Protocol::Tcp,
            ));
            (
                host.clone(),
                TokioAsyncResolver::tokio(config, Default::default()),
            )
        })
        .collect();
    let timeout = cfg.get_short_timeout();
    for (host, server) in servers {
        match tokio::time::timeout(timeout, lookup_domain_on(&host, &server, &domains, &cidrs))
            .await
        {
            Ok(result) => match result {
                Some((domain, cidr)) => {
                    log::info!("Found domain {} for host {}", domain, host);
                    if let Err(err) = do_ldap(&host, domain, &cidr, cfg).await {
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
