use crate::config::Config;
use crate::run::config::lookup_host;
use crate::run::script::{run_script_all, RunScriptArgs};
use crate::{ldap, rdp};
use anyhow::Context;
use cidr::IpCidr;
use clap::Args;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig};
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tokio::task::JoinSet;

pub async fn hostname(_cmd: (), cfg: &mut Config) -> anyhow::Result<()> {
    let script = PathBuf::from("hostname.sh");
    let mut set = run_script_all(cfg, RunScriptArgs::new(script)).await?;
    while let Some(joined) = set.join_next().await {
        let (mut host, output) = joined.context("Error running hostname script")?;
        match output {
            Ok(output) => {
                let alias = output.trim();
                log::info!("Got alias {} for host {}", alias, host.ip);
                host.aliases.insert(alias.into());
                cfg.add_host(&host);
            }
            Err(err) => {
                log::error!("Error running script on host {}: {}", host.ip, err);
            }
        }
    }
    Ok(())
}

#[derive(Args)]
pub struct LdapCommand {
    pub host: Option<String>,
}

pub async fn ldap(cmd: LdapCommand, cfg: &mut Config) -> anyhow::Result<()> {
    if let Some(host) = cmd.host {
        let host = lookup_host(cfg, &host)?;
        let domain = host
            .aliases
            .iter()
            .map(|alias| alias.splitn(2, '.').collect::<Vec<_>>())
            .filter_map(|alias| {
                if alias.len() == 2 {
                    Some(alias[1].to_owned())
                } else {
                    None
                }
            })
            .next()
            .context("no domain aliases for host")?;
        let pass = host.pass.as_ref().context("no password set for host")?;
        ldap::list_computers(host.ip, &domain, pass).await
    } else {
        log::info!("No host provided, trying DNS resolution");
        let cidr = cfg
            .get_cidr()
            .map(|cidr| match cidr {
                IpCidr::V4(cidr) => Some(cidr),
                _ => None,
            })
            .context("cidr is ipv6, not supported")?
            .context("no cidr set; have you run a scan?")?;
        // Collect all aliases of all hosts, then find only the ones
        // that are of the form "<name>.<domainpart>.<domainpart>..."
        let hosts = cfg.hosts();
        let domains: HashSet<_> = hosts
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
            .collect();
        log::info!("Found domains {:?}", domains);
        let mut lookup_cfg = ResolverConfig::new();
        // Find all the DNS servers we've found and add them
        hosts
            .iter()
            .filter(|(_, host)| host.open_ports.contains(&53))
            .for_each(|(ip, _)| {
                log::info!("Adding DNS server {}", ip);
                lookup_cfg.add_name_server(NameServerConfig::new(
                    (ip.clone(), 53).into(),
                    Protocol::Tcp,
                ))
            });
        let lookup = TokioAsyncResolver::tokio(lookup_cfg, Default::default());
        // This is the mask but with only the bottom bits set, not the top
        let inv_mask = !cidr.mask().to_bits();
        let subrange = cidr.first_address().to_bits() & cidr.mask().to_bits();
        // TODO: Use JoinSet!
        for domain in domains {
            match lookup.ipv4_lookup(&domain).await {
                Ok(ips) => {
                    for ip in ips {
                        let public_ip = Ipv4Addr::from_bits(ip.to_bits() & inv_mask | subrange);
                        match cfg
                            .hosts()
                            .iter()
                            .find(|(ip, _)| **ip == IpAddr::from(public_ip))
                        {
                            Some((ip, host)) => match &host.pass {
                                Some(pass) => {
                                    println!("Got DC {}", ip);
                                    match ldap::list_computers(ip.clone(), &domain, &pass).await {
                                        Ok(()) => continue,
                                        Err(err) => log::error!("LDAP failed: {}", err),
                                    }
                                }
                                None => continue,
                            },
                            None => continue,
                        }
                    }
                }
                Err(err) => log::error!("Failed to lookup IP for domain {}: {}", domain, err),
            }
        }
        Ok(())
    }
}

pub async fn rdp(_cmd: (), cfg: &mut Config) -> anyhow::Result<()> {
    let timeout = cfg.get_timeout();
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
                log::info!("Got name {} for host {}", name, host.ip);
                host.aliases.insert(name);
                cfg.add_host(&host);
            }
            Err(err) => {
                log::error!("Failed to get rdp hostname for host {}: {}", host.ip, err);
            }
        }
    }
    Ok(())
}
