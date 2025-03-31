use crate::config::{Config, Host, Password, Passwords};
use crate::proto::ssh::Session;
use crate::run::{
    config::lookup_host,
    script::{run_script_all_args, run_script_args, RunScriptArgs},
};

use anyhow::Context;
use clap::{Args, Subcommand};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Subcommand)]
#[command(about = "Password related commands.")]
pub enum PassCommand {
    #[command(about = "Check all hosts to see which hosts have insecure passwords.")]
    Check,
    Change(ChangeCommand),
}

pub async fn pass(cmd: PassCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd {
        PassCommand::Change(cmd) => change(cmd, cfg).await,
        PassCommand::Check => check((), cfg).await,
    }
}

async fn check(_cmd: (), cfg: &mut Config) -> anyhow::Result<()> {
    for (ip, host) in cfg.hosts() {
        let Some(pass) = &host.pass else {
            continue;
        };
    }
    Ok(())
}

#[derive(Args)]
#[command(about = "Rotate passwords on detected hosts, or a specific host specified.")]
pub struct ChangeCommand {
    host: Option<String>,
}

async fn change_one(mut host: Host, cfg: &mut Config) -> anyhow::Result<()> {
    let script = PathBuf::from("chpass.sh");
    let mut passwords = Passwords::from_file()?;
    let pass = passwords.random();
    log::info!("Using password {} for host", pass.id);
    let (code, pass) = run_script_args(
        cfg.get_long_timeout(),
        &host,
        RunScriptArgs::new(script).set_args(vec![host.user.clone(), pass.password]),
    )
    .await?;
    if code != 0 {
        log::trace!(
            "Password script returned nonzero code {} for host {}",
            code,
            host
        );
    }
    log::trace!(
        "Ran password script on host, now checking password {}",
        pass
    );
    let pass = pass.trim();
    let session = Session::connect(&host.user, pass, (host.ip, host.port)).await;
    match session {
        Err(err) => {
            log::trace!("Password change seems to have failed, error: {}", err);
        }
        Ok(mut session) => {
            log::trace!("Success, writing config file");
            host.pass = Some(pass.into());
            cfg.add_host(&host);
            _ = session.close().await;
        }
    }
    Ok(())
}

async fn change_many(cfg: &mut Config) -> anyhow::Result<()> {
    let script = PathBuf::from("chpass.sh");
    let mut passwords = Passwords::from_file()?;
    let mut map: HashMap<IpAddr, Password> = HashMap::new();
    let mut set = run_script_all_args(
        cfg.get_long_timeout(),
        cfg,
        |host| {
            let pass = passwords.random();
            log::info!("Using password {} for host {}", pass.id, host);
            map.insert(host.ip, pass.clone());
            vec![host.user.clone(), pass.password]
        },
        RunScriptArgs::new(script),
    )
    .await;
    let mut failed = Vec::<(String, String)>::new();
    while let Some(joined) = set.join_next().await {
        let (mut host, output) = joined.context("Error running password script")?;
        match output {
            Ok((code, pass)) => {
                if code != 0 {
                    log::trace!(
                        "Password script returned nonzero code {} for host {}",
                        code,
                        host
                    );
                }
                let pass = pass.trim();
                log::trace!(
                    "Ran password script on host {}, now checking password {}",
                    host,
                    pass
                );
                let session = Session::connect(&host.user, pass, (host.ip, host.port)).await;
                match session {
                    Err(err) => {
                        log::trace!("Password change seems to have failed, error: {}", err);
                        failed.push((host.to_string(), err.to_string()));
                    }
                    Ok(mut session) => {
                        log::trace!("Success, writing config file");
                        host.pass = Some(pass.into());
                        cfg.add_host(&host);
                        _ = session.close().await;
                    }
                }
            }
            Err(err) => {
                log::trace!("Error running script on host {}: {}", host, err);
                failed.push((host.to_string(), err.to_string()));
            }
        }
    }
    log::info!("Total: {} failed password changes", failed.len(),);
    for (host, error) in failed {
        log::info!("Host {}: {}", host, error);
    }
    Ok(())
}

async fn change(cmd: ChangeCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd.host {
        Some(host) => {
            let host = lookup_host(cfg, &host)?.clone();
            change_one(host, cfg).await
        }
        None => change_many(cfg).await,
    }
}
