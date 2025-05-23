use crate::config::{Config, Host};
use crate::scan::OsType;
use crate::util::strings::{comma_join, join};
use anyhow::Context;
use clap::{Args, Subcommand, ValueEnum};
use humantime::format_duration;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

fn parse_octets(host: &str) -> anyhow::Result<Vec<u8>> {
    Ok(host
        .split(".")
        .map(|seg| seg.parse::<u8>())
        .collect::<Result<_, _>>()?)
}

pub fn lookup_host<'a>(cfg: &'a Config, host: &str) -> anyhow::Result<&'a Host> {
    match host.parse() {
        Ok(ip) => cfg
            .host_for_ip(ip)
            .with_context(|| format!("no host for ip {}", ip)),
        Err(_) => match parse_octets(host) {
            Ok(octets) => cfg
                .host_for_octets(&octets)
                .with_context(|| format!("no host for octets {}", host)),
            Err(_) => cfg
                .host_for_alias(host)
                .with_context(|| format!("no host for alias {}", host)),
        },
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
        desc: HashSet::new(),
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
    let mut host = lookup_host(cfg, &cmd.host)?.clone();
    match cmd.cmd {
        EditCommandEnum::User(cmd) => host.user = cmd.user,
        EditCommandEnum::Pass(cmd) => host.pass = Some(cmd.pass),
        EditCommandEnum::Os(cmd) => host.os = cmd.os,
        EditCommandEnum::Alias(cmd) => _ = host.aliases.insert(cmd.alias),
    }
    cfg.add_host(&host);
    Ok(())
}

#[derive(Args)]
#[command(about = "List all existing hosts in the config.")]
pub struct ListCommand {
    pub os: Option<OsType>,
}

pub async fn list_hosts(cmd: ListCommand, cfg: &mut Config) -> anyhow::Result<()> {
    let mut hosts: Vec<_> = cfg
        .hosts()
        .values()
        .filter(|host| cmd.os.is_none() || Some(host.os) == cmd.os)
        .collect();
    hosts.sort_by_key(|host| host.ip);
    for host in hosts {
        let aliases: Vec<String> = host.aliases.iter().cloned().collect();
        let aliases = if aliases.len() == 0 {
            "<none>".into()
        } else {
            aliases.join(", ")
        };
        let hoststr = format!("{}@{}:{}", host.user, host.ip, host.port);
        println!("{:<55} (aliases {})", hoststr, aliases);
    }
    println!(
        "Octets excluded from scripts: {}",
        comma_join(cfg.get_excluded_octets())
    );
    Ok(())
}

#[derive(Args)]
#[command(about = "Get detailed information about a host.")]
pub struct InfoCommand {
    pub host: String,
}

pub async fn host_info(cmd: InfoCommand, cfg: &mut Config) -> anyhow::Result<()> {
    let host = lookup_host(cfg, &cmd.host)?;
    let aliases = if host.aliases.len() == 0 {
        "<none>".into()
    } else {
        comma_join(&host.aliases)
    };
    let ports = comma_join(&host.open_ports);
    println!("{} (aliases {})", host.ip, aliases);
    println!("Open ports: {}", ports);
    println!(
        "Password: {}",
        host.pass.as_ref().unwrap_or(&"<none>".into())
    );
    println!("Operating system: {:?}", host.os);
    println!("Description: {}", join(&host.desc, "\n             "));
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
#[command(about = "Octets to exclude when running scripts.")]
pub struct ExcludeCommand {
    pub octets: Vec<u8>,
}

pub async fn exclude(cmd: ExcludeCommand, cfg: &mut Config) -> anyhow::Result<()> {
    cfg.set_excluded_octets(&cmd.octets);
    Ok(())
}

#[derive(Args)]
#[command(about = "Import config in compatibility mode.")]
pub struct ImportCommand {
    pub filename: PathBuf,
}

pub async fn import(cmd: ImportCommand, cfg: &mut Config) -> anyhow::Result<()> {
    cfg.import_compat(&cmd.filename)
}

#[derive(Clone, PartialEq, Eq, ValueEnum)]
pub enum TimeoutType {
    Short,
    Long,
}

#[derive(Args)]
#[command(about = "Set or get global script / connection timeout.")]
pub struct TimeoutCommand {
    #[clap(value_parser = humantime::parse_duration)]
    #[arg(short, long)]
    pub timeout: Option<Duration>,

    #[arg(default_value = "short")]
    pub kind: TimeoutType,
}

pub async fn set_timeout(cmd: TimeoutCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd.timeout {
        Some(timeout) => match cmd.kind {
            TimeoutType::Short => cfg.set_short_timeout(timeout),
            TimeoutType::Long => cfg.set_long_timeout(timeout),
        },
        None => match cmd.kind {
            TimeoutType::Short => println!(
                "Short timeout is {}",
                format_duration(cfg.get_short_timeout())
            ),

            TimeoutType::Long => println!(
                "Long timeout is {}",
                format_duration(cfg.get_long_timeout())
            ),
        },
    }
    Ok(())
}
