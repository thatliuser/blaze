use crate::config::{Config, Host};
use crate::scan::OsType;
use anyhow::Context;
use clap::{Args, Subcommand};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

pub fn lookup_host<'a>(cfg: &'a Config, host: &str) -> anyhow::Result<&'a Host> {
    match host.parse() {
        Ok(ip) => cfg
            .host_for_ip(ip)
            .with_context(|| format!("no host for ip {}", ip)),
        Err(_) => cfg
            .host_for_alias(host)
            .with_context(|| format!("no host for alias {}", host)),
    }
}

pub fn lookup_host_mut<'a>(cfg: &'a mut Config, host: &str) -> anyhow::Result<&'a mut Host> {
    match host.parse() {
        Ok(ip) => cfg
            .host_for_ip_mut(ip)
            .with_context(|| format!("no host for ip {}", ip)),
        Err(_) => cfg
            .host_for_alias_mut(host)
            .with_context(|| format!("no host for alias {}", host)),
    }
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

pub async fn add_host(cmd: AddCommand, cfg: &mut Config) -> anyhow::Result<()> {
    cfg.add_host(&Host {
        ip: cmd.ip,
        user: cmd.user,
        pass: Some(cmd.pass),
        port: cmd.port,
        open_ports: HashSet::new(),
        aliases: HashSet::new(),
        os: cmd.os,
    });
    Ok(())
}

#[derive(Args)]
#[command(about = "Manually remove a host.")]
pub struct RemoveCommand {
    pub host: String,
}

pub async fn remove_host(cmd: RemoveCommand, cfg: &mut Config) -> anyhow::Result<()> {
    let ip = {
        let host = lookup_host(&cfg, &cmd.host)?;
        host.ip.clone()
    };
    cfg.remove_host(&ip);
    Ok(())
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

pub async fn edit_host(cmd: EditCommand, cfg: &mut Config) -> anyhow::Result<()> {
    let host = lookup_host_mut(cfg, &cmd.host)?;
    match cmd.cmd {
        EditCommandEnum::User(cmd) => host.user = cmd.user,
        EditCommandEnum::Pass(cmd) => host.pass = Some(cmd.pass),
        EditCommandEnum::Os(cmd) => host.os = cmd.os,
        EditCommandEnum::Alias(cmd) => _ = host.aliases.insert(cmd.alias),
    }
    Ok(())
}

#[derive(Args)]
#[command(about = "List all existing hosts in the config.")]
pub struct ListCommand {
    pub os: Option<OsType>,
}

pub async fn list_hosts(cmd: ListCommand, cfg: &mut Config) -> anyhow::Result<()> {
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
    Ok(())
}

#[derive(Args)]
#[command(about = "Export config in compatibility mode.")]
pub struct ExportCommand {
    pub filename: PathBuf,
}

pub async fn export(cmd: ExportCommand, cfg: &mut Config) -> anyhow::Result<()> {
    cfg.export_compat(&cmd.filename)
}

#[derive(Args)]
#[command(about = "Import config in compatibility mode.")]
pub struct ImportCommand {
    pub filename: PathBuf,
}

pub async fn import(cmd: ImportCommand, cfg: &mut Config) -> anyhow::Result<()> {
    cfg.import_compat(&cmd.filename)
}

#[derive(Args)]
#[command(about = "Set global script timeout.")]
pub struct TimeoutCommand {
    #[clap(value_parser = humantime::parse_duration)]
    pub timeout: Duration,
}

pub async fn set_timeout(cmd: TimeoutCommand, cfg: &mut Config) -> anyhow::Result<()> {
    cfg.set_timeout(cmd.timeout);
    Ok(())
}
