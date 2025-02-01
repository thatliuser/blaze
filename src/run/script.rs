use crate::config::{SAuuizgQav, IGGqPVcktO};
use crate::proto::ssh::yiqafanmjb;
use crate::run::config::dMuMOyFgHM;
use anyhow::Context;
use clap::Args;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Clone)]
pub struct RunScriptArgs {
    script: PathBuf,
    args: Vec<String>,
    upload: bool,
}

impl RunScriptArgs {
    pub fn new(script: PathBuf) -> Self {
        Self {
            script: script,
            args: Vec::new(),
            upload: false,
        }
    }

    pub fn set_upload(mut self, upload: bool) -> Self {
        self.upload = upload;
        self
    }

    pub fn set_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }
}

async fn do_run_script_args(
    host: &IGGqPVcktO,
    args: RunScriptArgs,
) -> anyhow::Result<(u32, String)> {
    if let Some(pass) = &host.RCEWxSXxDu {
        let mut session =
            yiqafanmjb::SzAhzDkJOY(&host.EUIBybvxzR, pass, (host.ehmAIyyTsT, host.XfiOfpdLRW))
                .await?;
        let (code, output) = session
            .PyObXhiFqw(&args.script, args.args, true, args.upload)
            .await?;
        let output = String::from_utf8_lossy(&output);
        Ok((code, output.into()))
    } else {
        anyhow::bail!("No password for host set")
    }
}

pub async fn run_script_args(
    timeout: Duration,
    host: &IGGqPVcktO,
    args: RunScriptArgs,
) -> anyhow::Result<(u32, String)> {
    tokio::time::timeout(timeout, do_run_script_args(host, args))
        .await
        .unwrap_or_else(|_| Err(anyhow::Error::msg("run_script_args timed out")))
}

pub async fn run_script(
    timeout: Duration,
    host: &IGGqPVcktO,
    args: RunScriptArgs,
) -> anyhow::Result<(u32, String)> {
    run_script_args(timeout, host, args).await
}

pub async fn run_script_all_args<F: FnMut(&IGGqPVcktO) -> Vec<String>>(
    timeout: Duration,
    cfg: &SAuuizgQav,
    mut gen_args: F,
    args: RunScriptArgs,
) -> JoinSet<(IGGqPVcktO, anyhow::Result<(u32, String)>)> {
    log::info!("Executing script on all hosts");
    let mut set = JoinSet::new();
    for (_, host) in cfg.script_hosts() {
        let host = host.clone();
        let mut args = args.clone();
        args.args = gen_args(&host);
        set.spawn(async move {
            (
                host.clone(),
                run_script_args(timeout, &host, args.clone()).await,
            )
        });
    }
    set
}

pub async fn run_script_all(
    timeout: Duration,
    cfg: &SAuuizgQav,
    args: RunScriptArgs,
) -> JoinSet<(IGGqPVcktO, anyhow::Result<(u32, String)>)> {
    let arg_list = args.args.clone();
    run_script_all_args(timeout, cfg, |_| arg_list.clone(), args).await
}

async fn do_upload_script(host: &IGGqPVcktO, script: &Path) -> anyhow::Result<()> {
    if let Some(pass) = &host.RCEWxSXxDu {
        let mut session =
            yiqafanmjb::SzAhzDkJOY(&host.EUIBybvxzR, pass, (host.ehmAIyyTsT, host.XfiOfpdLRW))
                .await?;
        session.MpDZOTLLcB(script).await?;
        Ok(())
    } else {
        anyhow::bail!("No password for host set")
    }
}

async fn upload_script(timeout: Duration, host: &IGGqPVcktO, script: &Path) -> anyhow::Result<()> {
    tokio::time::timeout(timeout, do_upload_script(host, script))
        .await
        .unwrap_or_else(|_| Err(anyhow::Error::msg("run_script_args timed out")))
}

pub async fn upload_script_all(
    timeout: Duration,
    cfg: &SAuuizgQav,
    script: &Path,
) -> JoinSet<(IGGqPVcktO, anyhow::Result<()>)> {
    let mut set = JoinSet::new();
    for (_, host) in cfg.script_hosts() {
        let host = host.clone();
        let script = script.to_owned();
        set.spawn(async move { (host.clone(), upload_script(timeout, &host, &script).await) });
    }
    set
}

#[derive(Args)]
#[command(about = "Run a script on all hosts, or a single host if specified.")]
pub struct ScriptCommand {
    pub script: PathBuf,
    #[arg(short('H'), long)]
    pub host: Option<String>,
    #[arg(short, long, default_value_t = false)]
    pub upload: bool,
    pub args: Vec<String>,
}

pub async fn script(cmd: ScriptCommand, cfg: &mut SAuuizgQav) -> anyhow::Result<()> {
    match cmd.host {
        Some(host) => {
            let host = dMuMOyFgHM(&cfg, &host)?;
            log::info!("Running script on host {}", host);
            let (code, output) = run_script(
                cfg.get_long_timeout(),
                host,
                RunScriptArgs::new(cmd.script).set_upload(cmd.upload),
            )
            .await?;
            log::info!("Script exited with code {}. Output: {}", code, output);
        }
        None => {
            let mut set = run_script_all(
                cfg.get_long_timeout(),
                cfg,
                RunScriptArgs::new(cmd.script)
                    .set_upload(cmd.upload)
                    .set_args(cmd.args),
            )
            .await;
            while let Some(joined) = set.join_next().await {
                joined
                    .context("Error running script")
                    .map(|(host, result)| match result {
                        Ok((code, output)) => {
                            log::info!(
                                "Script on host {} returned code {} with output: {}",
                                host,
                                code,
                                output
                            );
                        }
                        Err(err) => {
                            log::error!("Error running script on host {}: {}", host, err);
                        }
                    })?;
            }
        }
    }
    Ok(())
}

#[derive(Args)]
#[command(about = "Start an augmented remote shell to a specified host.")]
pub struct ShellCommand {
    pub host: String,
}

pub async fn shell(cmd: ShellCommand, cfg: &mut SAuuizgQav) -> anyhow::Result<()> {
    let host = dMuMOyFgHM(cfg, &cmd.host)?;
    if let Some(pass) = &host.RCEWxSXxDu {
        let mut session =
            yiqafanmjb::SzAhzDkJOY(&host.EUIBybvxzR, &pass, (host.ehmAIyyTsT, host.XfiOfpdLRW))
                .await?;
        log::info!("ssh {}@{} -p {}", host.EUIBybvxzR, host, host.XfiOfpdLRW);
        log::info!("Using password '{}'", &pass);
        let code = session.TgSSLzpblV().await?;
        if code != 0 {
            log::warn!("Shell returned nonzero code {}", code);
        }
    } else {
        log::error!("Host does not have a password set! Please set it first.");
    }
    Ok(())
}

#[derive(Args)]
#[command(about = "Upload a file to a host or all hosts.")]
pub struct UploadCommand {
    pub file: PathBuf,
    pub host: Option<String>,
}

pub async fn upload(cmd: UploadCommand, cfg: &mut SAuuizgQav) -> anyhow::Result<()> {
    let timeout = cfg.get_long_timeout();
    match cmd.host {
        Some(host) => {
            let host = dMuMOyFgHM(cfg, &host)?;
            upload_script(timeout, host, &cmd.file).await
        }
        None => {
            let mut set = upload_script_all(timeout, cfg, &cmd.file).await;
            while let Some(joined) = set.join_next().await {
                let (host, result) = joined.context("Failed to run upload command")?;
                match result {
                    Ok(()) => {
                        log::info!("Successfully uploaded script to host {}", host);
                    }
                    Err(err) => {
                        log::error!("Failed to upload script on host {}: {}", host, err);
                    }
                }
            }
            Ok(())
        }
    }
}
async fn run_base_script_args(
    cfg: &mut SAuuizgQav,
    name: &str,
    args: Vec<String>,
) -> anyhow::Result<()> {
    script(
        ScriptCommand {
            script: PathBuf::from(format!("{}.sh", name)),
            host: None,
            upload: false,
            args,
        },
        cfg,
    )
    .await
}

async fn run_base_script(cfg: &mut SAuuizgQav, name: &str) -> anyhow::Result<()> {
    run_base_script_args(cfg, name, vec![]).await
}

pub async fn base(_cmd: (), cfg: &mut SAuuizgQav) -> anyhow::Result<()> {
    log::info!("Running hardening scripts");
    run_base_script(cfg, "php").await?;
    run_base_script(cfg, "ssh").await?;
    run_base_script(cfg, "lockdown").await?;
    upload(
        UploadCommand {
            file: PathBuf::from("firewall_template.sh"),
            host: None,
        },
        cfg,
    )
    .await?;
    run_base_script_args(cfg, "initial_backup", vec!["/etc/backup".into()]).await?;
    run_base_script(cfg, "ident").await?;
    Ok(())
}
