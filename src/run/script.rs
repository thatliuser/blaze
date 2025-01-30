use crate::config::{Config, Host};
use crate::run::config::lookup_host;
use crate::ssh::Session;
use anyhow::Context;
use clap::Args;
use std::path::PathBuf;
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

async fn do_run_script_args(host: &Host, args: RunScriptArgs) -> anyhow::Result<String> {
    if let Some(pass) = &host.pass {
        let mut session = Session::connect(&host.user, pass, (host.ip, host.port)).await?;
        let (code, output) = session
            .run_script(&args.script, args.args, true, args.upload)
            .await?;
        let output = String::from_utf8_lossy(&output);
        if code != 0 {
            anyhow::bail!("script returned nonzero code {}", code);
        } else {
            Ok(output.into())
        }
    } else {
        anyhow::bail!("No password for host set")
    }
}

pub async fn run_script_args(
    timeout: Duration,
    host: &Host,
    args: RunScriptArgs,
) -> anyhow::Result<String> {
    tokio::time::timeout(timeout, do_run_script_args(host, args))
        .await
        .unwrap_or_else(|_| Err(anyhow::Error::msg("run_script_args timed out")))
}

pub async fn run_script(
    timeout: Duration,
    host: &Host,
    args: RunScriptArgs,
) -> anyhow::Result<String> {
    run_script_args(timeout, host, args).await
}

pub async fn run_script_all_args<F: FnMut(&Host) -> Vec<String>>(
    cfg: &Config,
    mut gen_args: F,
    args: RunScriptArgs,
) -> anyhow::Result<JoinSet<(Host, anyhow::Result<String>)>> {
    log::info!("Executing script on all hosts");
    let mut set = JoinSet::new();
    for (_, host) in cfg.hosts() {
        let timeout = cfg.get_timeout();
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
    Ok(set)
}

pub async fn run_script_all(
    cfg: &Config,
    args: RunScriptArgs,
) -> anyhow::Result<JoinSet<(Host, anyhow::Result<String>)>> {
    let arg_list = args.args.clone();
    run_script_all_args(cfg, |_| arg_list.clone(), args).await
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

pub async fn script(cmd: ScriptCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd.host {
        Some(host) => {
            let host = lookup_host(&cfg, &host)?;
            log::info!("Running script on host {}", host.ip);
            let output = run_script(
                cfg.get_timeout(),
                host,
                RunScriptArgs::new(cmd.script).set_upload(cmd.upload),
            )
            .await?;
            log::info!("Script outputted: {}", output);
        }
        None => {
            let mut set = run_script_all(
                cfg,
                RunScriptArgs::new(cmd.script)
                    .set_upload(cmd.upload)
                    .set_args(cmd.args),
            )
            .await?;
            while let Some(joined) = set.join_next().await {
                joined
                    .context("Error running script")
                    .map(|(host, output)| match output {
                        Ok(output) => {
                            log::info!("Script on host {} outputted: {}", host.ip, output);
                        }
                        Err(err) => {
                            log::error!("Error running script on host {}: {}", host.ip, err);
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

pub async fn shell(cmd: ShellCommand, cfg: &mut Config) -> anyhow::Result<()> {
    let ip = cmd.host.parse().or_else(|_| {
        cfg.host_for_alias(&cmd.host)
            .map(|host| host.ip)
            .ok_or_else(|| anyhow::Error::msg("couldn't lookup host by alias"))
    })?;
    let host = cfg
        .host_for_ip(ip)
        .ok_or_else(|| anyhow::Error::msg("failed to get host for IP"))?;
    if let Some(pass) = &host.pass {
        let mut session = Session::connect(&host.user, &pass, (ip, host.port)).await?;
        log::info!("ssh {}@{} -p {}", host.user, host.ip, host.port);
        log::info!("Using password '{}'", &pass);
        let code = session.shell().await?;
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

pub async fn upload(cmd: UploadCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd.host {
        Some(host) => {
            let host = lookup_host(cfg, &host).context("couldn't lookup host")?;
            let pass = host.pass.as_ref().context("host has no password set")?;
            let mut session = Session::connect(&host.user, &pass, (host.ip, host.port)).await?;
            session.upload(&cmd.file).await?;
            Ok(())
        }
        None => {
            anyhow::bail!("Unimplemented at the moment");
        }
    }
}
