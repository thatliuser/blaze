use crate::config::{Config, Host};
use crate::proto::ssh::Session;
use crate::run::config::lookup_host;
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

async fn do_run_script_args(host: &Host, args: RunScriptArgs) -> anyhow::Result<(u32, String)> {
    if let Some(pass) = &host.pass {
        let mut session = Session::connect(&host.user, pass, (host.ip, host.port)).await?;
        let (code, output) = session
            .run_script(&args.script, args.args, true, args.upload)
            .await?;
        let output = String::from_utf8_lossy(&output);
        Ok((code, output.into()))
    } else {
        anyhow::bail!("No password for host set")
    }
}

pub async fn run_script_args(
    timeout: Duration,
    host: &Host,
    args: RunScriptArgs,
) -> anyhow::Result<(u32, String)> {
    tokio::time::timeout(timeout, do_run_script_args(host, args))
        .await
        .unwrap_or_else(|_| Err(anyhow::Error::msg("run_script_args timed out")))
}

pub async fn run_script(
    timeout: Duration,
    host: &Host,
    args: RunScriptArgs,
) -> anyhow::Result<(u32, String)> {
    run_script_args(timeout, host, args).await
}

pub async fn run_script_all_args<F: FnMut(&Host) -> Vec<String>>(
    timeout: Duration,
    cfg: &Config,
    mut gen_args: F,
    args: RunScriptArgs,
) -> JoinSet<(Host, anyhow::Result<(u32, String)>)> {
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
    cfg: &Config,
    args: RunScriptArgs,
) -> JoinSet<(Host, anyhow::Result<(u32, String)>)> {
    let arg_list = args.args.clone();
    run_script_all_args(timeout, cfg, |_| arg_list.clone(), args).await
}

async fn do_upload_script(host: &Host, script: &Path) -> anyhow::Result<()> {
    if let Some(pass) = &host.pass {
        let mut session = Session::connect(&host.user, pass, (host.ip, host.port)).await?;
        session.upload(script).await?;
        Ok(())
    } else {
        anyhow::bail!("No password for host set")
    }
}

async fn upload_script(timeout: Duration, host: &Host, script: &Path) -> anyhow::Result<()> {
    tokio::time::timeout(timeout, do_upload_script(host, script))
        .await
        .unwrap_or_else(|_| Err(anyhow::Error::msg("run_script_args timed out")))
}

pub async fn upload_script_all(
    timeout: Duration,
    cfg: &Config,
    script: &Path,
) -> JoinSet<(Host, anyhow::Result<()>)> {
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

pub async fn script(cmd: ScriptCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd.host {
        Some(host) => {
            let host = lookup_host(&cfg, &host)?;
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

pub async fn shell(cmd: ShellCommand, cfg: &mut Config) -> anyhow::Result<()> {
    let host = lookup_host(cfg, &cmd.host)?;
    if let Some(pass) = &host.pass {
        // Print specifically the host IP because needs to be copy-pastable into terminal
        log::info!("ssh {}@{} -p {}", host.user, host.ip, host.port);
        log::info!("Using password '{}'", &pass);
        let mut session = Session::connect(&host.user, &pass, (host.ip, host.port)).await?;
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

pub async fn upload(cmd: UploadCommand, cfg: &Config) -> anyhow::Result<()> {
    let timeout = cfg.get_long_timeout();
    match cmd.host {
        Some(host) => {
            let host = lookup_host(cfg, &host)?;
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
    cfg: &mut Config,
    name: &str,
    args: Vec<String>,
    host: Option<String>,
    upload: bool,
) -> anyhow::Result<()> {
    script(
        ScriptCommand {
            script: PathBuf::from(format!("{}.sh", name)),
            host: host,
            upload: upload,
            args,
        },
        cfg,
    )
    .await
}

async fn run_base_script(
    cfg: &mut Config,
    name: &str,
    host: Option<String>,
    upload: bool,
) -> anyhow::Result<()> {
    run_base_script_args(cfg, name, vec![], host, upload).await
}

#[derive(Args)]
#[command(about = "Run basic scripts across all hosts.")]
pub struct BaseCommand {
    pub host: Option<String>,
}

pub async fn base(cmd: BaseCommand, cfg: &mut Config) -> anyhow::Result<()> {
    log::info!("Running hardening scripts");
    run_base_script(cfg, "php", cmd.host.clone(), false).await?;
    run_base_script(cfg, "ssh", cmd.host.clone(), false).await?;
    run_base_script_args(
        cfg,
        "firewall_template",
        vec!["apply".into()],
        cmd.host.clone(),
        true,
    )
    .await?;
    // TODO: This is like, really stupid, and I should just support
    // uploading multiple files over the same SSH/SFTP channel
    // But for now I don't think I have the time to architect it, so I won't
    let (extract, parse) = tokio::join!(
        upload(
            UploadCommand {
                file: PathBuf::from("extract_fw_logs.sh"),
                host: cmd.host.clone(),
            },
            cfg,
        ),
        upload(
            UploadCommand {
                file: PathBuf::from("parse_fw_logs.sh"),
                host: cmd.host.clone(),
            },
            cfg,
        )
    );
    extract.context("Couldn't upload firewall log extractor script")?;
    parse.context("Couldn't upload firewall log parser script")?;
    run_base_script_args(
        cfg,
        "initial_backup",
        vec!["/etc/backup".into()],
        cmd.host.clone(),
        true,
    )
    .await?;
    run_base_script(cfg, "ident", cmd.host, true).await?;
    Ok(())
}
