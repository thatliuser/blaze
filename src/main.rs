// Entrypoint

mod config;
mod scan;
mod ssh;

use anyhow::Context;
use cidr::IpCidr;
use clap::{Args, Parser};
use config::{Config, Host};
use scan::{Backend, Scan};
use ssh::Runnable;
use ssh::Session;
use std::{collections::HashMap, net::IpAddr, path::PathBuf};
use tokio::task::JoinSet;

#[derive(Parser)]
enum BlazeCommand {
    #[clap(alias = "n")]
    Scan(ScanCommand),
    #[clap(alias = "a")]
    Add(AddCommand),
    #[clap(alias = "l")]
    #[command(about = "List all existing hosts in the config.")]
    List,
    #[clap(alias = "r")]
    #[command(about = "Detect the hostnames of all detected hosts.")]
    Resolve,
    #[clap(alias = "sc")]
    Script(ScriptCommand),
    #[clap(alias = "sh")]
    Shell(ShellCommand),
}

#[derive(Args)]
#[command(about = "Run an nmap scan on a specified subnet.")]
struct ScanCommand {
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
struct AddCommand {
    pub ip: IpAddr,
    #[arg(short, long, default_value_t = String::from("root"))]
    pub user: String,
    pub pass: String,
    #[arg(short, long, default_value_t = 22)]
    pub port: u16,
}

#[derive(Args)]
#[command(about = "Run a script on all hosts, or a single host if specified.")]
struct ScriptCommand {
    #[arg(long)]
    pub host: Option<String>,
    pub script: PathBuf,
}

#[derive(Args)]
#[command(about = "Start an augmented remote shell to a specified host.")]
struct ShellCommand {
    pub host: String,
}

fn lookup_host<'a>(cfg: &'a Config, host: &str) -> anyhow::Result<&'a Host> {
    host.parse()
        .context("couldn't parse ip address")
        .and_then(|ip| {
            cfg.host_for_ip(ip)
                .with_context(|| format!("no host found for ip {}", ip))
        })
        .or_else(|_| {
            cfg.host_for_alias(host)
                .with_context(|| format!("no host found for alias {}", host))
        })
}

async fn run_script(host: &Host, script: Runnable) -> anyhow::Result<String> {
    let mut session = Session::connect(&host.user, &host.pass, (host.ip, host.port)).await?;
    let (code, output) = session.exec(script, true).await?;
    let output = String::from_utf8_lossy(&output);
    if code != 0 {
        anyhow::bail!("script returned nonzero code");
    } else {
        Ok(output.into())
    }
}

async fn run_script_all(
    cfg: &Config,
    script: Runnable,
) -> anyhow::Result<JoinSet<(Host, anyhow::Result<String>)>> {
    println!("Executing script on all hosts");
    let mut set = JoinSet::new();
    for (_, host) in cfg.hosts() {
        let mut host = host.clone();
        let script = script.clone();
        set.spawn(async move { (host.clone(), run_script(&host, script).await) });
    }
    Ok(set)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cfg = Config::from(&PathBuf::from("blaze.yaml")).unwrap_or_else(|err| {
        println!("Error loading config: {:?}, loading default", err);
        Config::new()
    });
    match BlazeCommand::parse() {
        BlazeCommand::Scan(cmd) => {
            println!("Subnet: {:?}", cmd.subnet);
            let scan = Scan::new(&cmd.subnet, cmd.backend).await?;
            for host in scan.hosts.iter() {
                println!("{:?}: {:?}", host.addr, host.os);
                cfg.add_host_from(host, cmd.user.clone(), cmd.pass.clone(), cmd.port)?;
            }
        }
        BlazeCommand::Add(cmd) => {
            anyhow::bail!("Not implemented yet");
        }
        BlazeCommand::List => {
            for host in cfg.hosts().values() {
                println!("{:?}", host);
            }
        }
        BlazeCommand::Resolve => {
            let mut set = run_script_all(
                &mut cfg,
                Runnable::Command("echo $(hostname || cat /etc/hostname)".into()),
            )
            .await?;
            while let Some(joined) = set.join_next().await {
                match joined {
                    Err(err) => println!("Error running script: {}", err),
                    Ok((mut host, output)) => match output {
                        Ok(output) => {
                            let alias = output.trim();
                            println!("Got alias {} for host {}", alias, host.ip);
                            host.aliases.insert(alias.into());
                            cfg.add_host(&host);
                        }
                        Err(err) => {
                            println!("Error running script on host {}: {}", host.ip, err)
                        }
                    },
                }
            }
        }
        BlazeCommand::Script(cmd) => {
            let mut set = run_script_all(&mut cfg, Runnable::Script(cmd.script)).await?;
            while let Some(joined) = set.join_next().await {
                match joined {
                    Err(err) => println!("Error running script: {}", err),
                    Ok((host, output)) => match output {
                        Ok(output) => {
                            println!("Script on host {} outputted: {}", host.ip, output)
                        }
                        Err(err) => {
                            println!("Error running script on host {}: {}", host.ip, err)
                        }
                    },
                }
            }
        }
        BlazeCommand::Shell(cmd) => {
            let ip = cmd.host.parse().or_else(|_| {
                cfg.host_for_alias(&cmd.host)
                    .map(|host| host.ip)
                    .ok_or_else(|| anyhow::Error::msg("couldn't lookup host by alias"))
            })?;
            let host = cfg
                .host_for_ip(ip)
                .ok_or_else(|| anyhow::Error::msg("failed to get host for IP"))?;
            let mut session = Session::connect(&host.user, &host.pass, (ip, host.port)).await?;
            let code = session.shell().await?;
            if code != 0 {
                anyhow::bail!("shell returned nonzero code {}", code);
            }
        }
    }
    Ok(())
}
