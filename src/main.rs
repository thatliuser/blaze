// Entrypoint

mod config;
mod nmap;
mod ssh;

use clap::{Args, Parser};
use config::Config;
use config::Host;
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
    pub subnet: String,
    #[arg(short, long, default_value_t = String::from("root"))]
    pub user: String,
    pub pass: String,
    #[arg(short, long, default_value_t = 22)]
    pub port: u16,
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
#[command(about = "Run a script on all detected hosts.")]
struct ScriptCommand {
    pub host: String,
    pub script: PathBuf,
}

#[derive(Args)]
#[command(about = "Start an augmented remote shell to a specified host.")]
struct ShellCommand {
    pub host: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cfg = Config::from(&PathBuf::from("blaze.yaml")).unwrap_or_else(|err| {
        println!("Error loading config: {:?}, loading default", err);
        Config::new()
    });
    match BlazeCommand::parse() {
        BlazeCommand::Scan(cmd) => {
            println!("Subnet: {}", cmd.subnet);
            let scan = nmap::Scan::new(cmd.subnet)?;
            let hosts = scan.get_hosts();
            for host in hosts.iter() {
                println!("{:?}: {:?}", host.host.addresses(), host.os);
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
            let mut set = JoinSet::new();
            for (ip, host) in cfg.hosts() {
                let mut host = host.clone();
                let ip = ip.clone();
                set.spawn(async move {
                    let mut session =
                        Session::connect(&host.user, &host.pass, (ip, host.port)).await?;
                    let result = session
                        .exec(
                            Runnable::Command("echo $(hostname || cat /etc/hostname)".into()),
                            true,
                        )
                        .await?;
                    if result.0 != 0 {
                        anyhow::bail!("script returned nonzero code");
                    } else {
                        let alias = String::from_utf8(result.1)?.trim().into();
                        host.aliases.insert(alias);
                        Ok(host)
                    }
                });
            }
            while let Some(joined) = set.join_next().await {
                let res = joined?;
                match res {
                    Ok(host) => {
                        println!("Got alias for host {}: {:?}", host.ip, host.aliases);
                        cfg.add_host(&host);
                    }
                    Err(err) => {
                        println!("Script failed: {}", err);
                    }
                }
            }
        }
        BlazeCommand::Script(cmd) => {
            println!("Executing script {} on {}", cmd.script.display(), cmd.host);
            let ip = cmd.host.parse().or_else(|_| {
                cfg.host_for_alias(&cmd.host)
                    .map(|host| host.ip)
                    .ok_or_else(|| anyhow::Error::msg("couldn't lookup host by alias"))
            })?;
            let host = cfg
                .host_for_ip(ip)
                .ok_or_else(|| anyhow::Error::msg("failed to get host for IP"))?;
            let mut session = Session::connect(&host.user, &host.pass, (ip, host.port)).await?;
            let (code, output) = session.exec(Runnable::Script(cmd.script), true).await?;
            println!("Program returned code {}", code);
            println!("Output: {}", String::from_utf8_lossy(&output));
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
