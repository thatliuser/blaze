use crate::config::Config;
use crate::run::script::{run_script_all, RunScriptArgs};
use crate::{ldap, rdp};
use anyhow::Context;
use clap::Args;
use std::net::IpAddr;
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
    pub ip: IpAddr,
    pub domain: String,
    pub pass: String,
}

pub async fn ldap(cmd: LdapCommand, _cfg: &mut Config) -> anyhow::Result<()> {
    ldap::list_computers(cmd.ip, &cmd.domain, &cmd.pass).await
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
