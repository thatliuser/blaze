use crate::config::{Config, Host};
use crate::scan::{Backend, OsType, Scan};
use crate::ssh::Session;
use crate::{ldap, rdp};
use anyhow::Context;
use cidr::IpCidr;
use clap::{Args, Parser, Subcommand};
use rand::Rng;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Parser)]
pub enum BlazeCommand {
    Scan(ScanCommand),
    #[clap(alias = "a")]
    Add(AddCommand),
    #[clap(alias = "rm")]
    Remove(RemoveCommand),
    #[clap(alias = "ls")]
    List(ListCommand),
    #[clap(alias = "r")]
    #[command(about = "Detect the hostnames of all detected hosts.")]
    Resolve,
    #[command(about = "Change the login credentials of all detected hosts.")]
    Chpass,
    #[clap(alias = "sc")]
    Script(ScriptCommand),
    #[clap(alias = "sh")]
    Shell(ShellCommand),
    Timeout(TimeoutCommand),
    Export(ExportCommand),
    Edit(EditCommand),
    Ldap(LdapCommand),
    Rdp,
}

#[derive(Args)]
#[command(about = "Run a network scan on a specified subnet.")]
pub struct ScanCommand {
    pub subnet: IpCidr,
    #[arg(short, long, default_value_t = String::from("root"))]
    pub user: String,
    pub pass: String,
    #[arg(short, long, default_value_t = 22)]
    pub port: u16,
    #[arg(short, long, default_value_t = Backend::RustScan)]
    pub backend: Backend,
}

#[derive(Args)]
#[command(about = "Manually specify a new host.")]
pub struct AddCommand {
    pub ip: IpAddr,
    #[arg(short, long, default_value_t = String::from("root"))]
    pub user: String,
    pub pass: String,
    #[arg(short, long, default_value_t = 22)]
    pub port: u16,
    #[arg(short, long, default_value = "unix-like")]
    pub os: OsType,
}

#[derive(Args)]
#[command(about = "Manually remove a host.")]
pub struct RemoveCommand {
    pub host: String,
}

#[derive(Args)]
#[command(about = "List all existing hosts in the config.")]
pub struct ListCommand {
    pub os: Option<OsType>,
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

#[derive(Args)]
#[command(about = "Start an augmented remote shell to a specified host.")]
pub struct ShellCommand {
    pub host: String,
}

#[derive(Args)]
#[command(about = "Set global script timeout.")]
pub struct TimeoutCommand {
    #[clap(value_parser = humantime::parse_duration)]
    pub timeout: Duration,
}

#[derive(Args)]
#[command(about = "Export config in compatibility mode.")]
pub struct ExportCommand {
    pub filename: PathBuf,
}

#[derive(Args)]
pub struct EditCommand {
    pub host: String,
    #[command(subcommand)]
    pub cmd: EditCommandEnum,
}

#[derive(Subcommand)]
#[command(about = "Manually edit properties of a host.")]
pub enum EditCommandEnum {
    User(EditUserCommand),
    #[clap(alias = "pw")]
    Pass(EditPassCommand),
    Os(EditOsCommand),
    Alias(EditAliasCommand),
}

#[derive(Args)]
#[command(about = "Change the login user of a host.")]
pub struct EditUserCommand {
    pub user: String,
}

#[derive(Args)]
#[command(about = "Change the login password of a host.")]
pub struct EditPassCommand {
    pub pass: String,
}

#[derive(Args)]
#[command(about = "Change the OS of a host.")]
pub struct EditOsCommand {
    pub os: OsType,
}

#[derive(Args)]
#[command(about = "Add an alias to a host.")]
pub struct EditAliasCommand {
    pub alias: String,
}

#[derive(Args)]
pub struct LdapCommand {
    pub ip: IpAddr,
    pub domain: String,
    pub pass: String,
}

#[derive(Deserialize)]
struct Password {
    id: u32,
    password: String,
}

#[derive(Clone)]
struct RunScriptArgs {
    script: PathBuf,
    args: Vec<String>,
    upload: bool,
}

impl RunScriptArgs {
    fn new(script: PathBuf) -> Self {
        Self {
            script: script,
            args: Vec::new(),
            upload: false,
        }
    }

    fn set_upload(mut self, upload: bool) -> Self {
        self.upload = upload;
        self
    }

    fn set_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }
}

fn get_passwords() -> anyhow::Result<Vec<Password>> {
    let mut passwords = Vec::new();
    let mut reader = csv::Reader::from_path("passwords.db")?;
    for result in reader.deserialize() {
        passwords.push(result?);
    }
    Ok(passwords)
}

fn lookup_host<'a>(cfg: &'a Config, host: &str) -> anyhow::Result<&'a Host> {
    match host.parse() {
        Ok(ip) => cfg
            .host_for_ip(ip)
            .with_context(|| format!("no host for ip {}", ip)),
        Err(_) => cfg
            .host_for_alias(host)
            .with_context(|| format!("no host for alias {}", host)),
    }
}

fn lookup_host_mut<'a>(cfg: &'a mut Config, host: &str) -> anyhow::Result<&'a mut Host> {
    match host.parse() {
        Ok(ip) => cfg
            .host_for_ip_mut(ip)
            .with_context(|| format!("no host for ip {}", ip)),
        Err(_) => cfg
            .host_for_alias_mut(host)
            .with_context(|| format!("no host for alias {}", host)),
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

async fn run_script_args(
    timeout: Duration,
    host: &Host,
    args: RunScriptArgs,
) -> anyhow::Result<String> {
    tokio::time::timeout(timeout, do_run_script_args(host, args))
        .await
        .unwrap_or_else(|_| Err(anyhow::Error::msg("run_script_args timed out")))
}

async fn run_script(timeout: Duration, host: &Host, args: RunScriptArgs) -> anyhow::Result<String> {
    run_script_args(timeout, host, args).await
}

async fn run_script_all_args<F: FnMut(&Host) -> Vec<String>>(
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
async fn run_script_all(
    cfg: &Config,
    args: RunScriptArgs,
) -> anyhow::Result<JoinSet<(Host, anyhow::Result<String>)>> {
    let arg_list = args.args.clone();
    run_script_all_args(cfg, |_| arg_list.clone(), args).await
}

pub async fn run(cmd: BlazeCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd {
        BlazeCommand::Scan(cmd) => {
            log::debug!("Subnet: {:?}", cmd.subnet);
            let scan = Scan::new(&cmd.subnet, cmd.backend).await?;
            let mut set = JoinSet::new();
            for host in scan.hosts.iter() {
                log::info!("Got host {} with OS {:?}", host.addr, host.os);
                let host = host.clone();
                let timeout = cfg.get_timeout();
                set.spawn(async move { (host.clone(), host.try_detect_ssh(timeout).await) });
            }
            while let Some(joined) = set.join_next().await {
                let (mut host, result) = joined.context("Failed to spawn host ID detector")?;
                match result {
                    Ok((id, os)) => {
                        if os != host.os {
                            log::info!(
                                "Host {} OS changed from {:?} to {:?} (SSH ID {})",
                                host.addr,
                                host.os,
                                os,
                                id
                            );
                            host.os = os;
                        }
                    }
                    Err(err) => {
                        log::error!("Failed to detect host {} ID from SSH: {}", host.addr, err);
                    }
                }
                cfg.add_host_from(&host, cmd.user.clone(), Some(cmd.pass.clone()), cmd.port)?;
            }
            for host in cfg.hosts() {}
        }
        BlazeCommand::Add(cmd) => cfg.add_host(&Host {
            ip: cmd.ip,
            user: cmd.user,
            pass: Some(cmd.pass),
            port: cmd.port,
            open_ports: HashSet::new(),
            aliases: HashSet::new(),
            os: cmd.os,
        }),
        BlazeCommand::Remove(cmd) => {
            let ip = {
                let host = lookup_host(&cfg, &cmd.host)?;
                host.ip.clone()
            };
            cfg.remove_host(&ip);
        }
        BlazeCommand::Edit(cmd) => {
            let host = lookup_host_mut(cfg, &cmd.host)?;
            match cmd.cmd {
                EditCommandEnum::User(cmd) => host.user = cmd.user,
                EditCommandEnum::Pass(cmd) => host.pass = Some(cmd.pass),
                EditCommandEnum::Os(cmd) => host.os = cmd.os,
                EditCommandEnum::Alias(cmd) => _ = host.aliases.insert(cmd.alias),
            }
        }
        BlazeCommand::List(cmd) => {
            for host in cfg
                .hosts()
                .values()
                .filter(|host| cmd.os.is_none() || Some(host.os) == cmd.os)
            {
                let aliases: Vec<String> = host.aliases.iter().cloned().collect();
                let aliases = if aliases.len() == 0 {
                    "<none>".into()
                } else {
                    aliases.join(", ")
                };
                let hoststr = format!("{}@{}:{}", host.user, host.ip, host.port);
                println!("{:<25} (aliases {})", hoststr, aliases);
            }
        }
        BlazeCommand::Resolve => {
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
        }
        BlazeCommand::Chpass => {
            let script = PathBuf::from("chpass.sh");
            let mut passwords = get_passwords()?;
            let mut rng = rand::thread_rng();
            let mut set = run_script_all_args(
                cfg,
                |host| {
                    let rand = rng.gen_range(0..passwords.len());
                    let pass = passwords.remove(rand);
                    log::info!("Using password {} for host {}", pass.id, host.ip);
                    vec![host.user.clone(), pass.password]
                },
                RunScriptArgs::new(script),
            )
            .await?;
            let mut failed = Vec::<String>::new();
            while let Some(joined) = set.join_next().await {
                let (mut host, output) = joined.context("Error running password script")?;
                match output {
                    Ok(pass) => {
                        let pass = pass.trim();
                        log::info!(
                            "Ran password script on host {}, now checking password {}",
                            host.ip,
                            pass
                        );
                        let session =
                            Session::connect(&host.user, pass, (host.ip, host.port)).await;
                        if let Err(err) = session {
                            log::error!("Password change seems to have failed, error: {}", err);
                            failed.push(format!("{}", host.ip));
                        } else {
                            log::info!("Success, writing config file");
                            host.pass = Some(pass.into());
                            cfg.add_host(&host);
                        }
                    }
                    Err(err) => {
                        log::error!("Error running script on host {}: {}", host.ip, err);
                        failed.push(format!("{}", host.ip));
                    }
                }
            }
            log::info!(
                "Total: {} failed password changes (hosts {:?})",
                failed.len(),
                failed.join(" "),
            );
        }
        BlazeCommand::Script(cmd) => match cmd.host {
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
        },
        BlazeCommand::Shell(cmd) => {
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
        }
        BlazeCommand::Export(cmd) => cfg.export_compat(&cmd.filename)?,
        BlazeCommand::Timeout(cmd) => cfg.set_timeout(cmd.timeout),
        BlazeCommand::Ldap(cmd) => ldap::list_computers(cmd.ip, &cmd.domain, &cmd.pass).await?,
        BlazeCommand::Rdp => {
            let timeout = cfg.get_timeout();
            let mut set = JoinSet::new();
            for (_, host) in cfg
                .hosts()
                .iter()
                .filter(|(_, host)| host.open_ports.contains(&3389))
            {
                let host = host.clone();
                set.spawn(
                    async move { (host.clone(), rdp::grab_rdp_hostname(host.ip, timeout).await) },
                );
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
        }
    }
    Ok(())
}
