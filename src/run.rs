use crate::config::{Config, Host};
use crate::scan::{Backend, Scan};
use crate::ssh::Session;
use anyhow::Context;
use cidr::IpCidr;
use clap::{Args, CommandFactory, Parser};
use rand::Rng;
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Duration;
use tokio::task::JoinSet;

#[derive(Parser)]
pub enum BlazeCommand {
    Scan(ScanCommand),
    #[clap(alias = "a")]
    Add(AddCommand),
    #[clap(alias = "pw")]
    Password(PasswordCommand),
    #[clap(alias = "ls")]
    #[command(about = "List all existing hosts in the config.")]
    List,
    #[clap(alias = "r")]
    #[command(about = "Detect the hostnames of all detected hosts.")]
    Resolve,
    #[command(about = "Change the login credentials of all detected hosts.")]
    Chpass,
    #[clap(alias = "sc")]
    Script(ScriptCommand),
    #[clap(alias = "sh")]
    Shell(ShellCommand),
}

#[derive(Args)]
#[command(about = "Run an nmap scan on a specified subnet.")]
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
}

#[derive(Args)]
#[command(about = "Run a script on all hosts, or a single host if specified.")]
pub struct ScriptCommand {
    pub script: String,
    pub host: Option<String>,
}

#[derive(Args)]
#[command(about = "Start an augmented remote shell to a specified host.")]
pub struct ShellCommand {
    pub host: String,
}

#[derive(Args)]
#[command(about = "Change the password of a host.")]
pub struct PasswordCommand {
    pub host: String,
    pub pass: String,
}

#[derive(Deserialize)]
struct Password {
    id: u32,
    password: String,
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

async fn do_run_script_args(
    host: &Host,
    script: &str,
    args: Vec<String>,
) -> anyhow::Result<String> {
    let mut session = Session::connect(&host.user, &host.pass, (host.ip, host.port)).await?;
    let (code, output) = session.run_script(script, args, true).await?;
    let output = String::from_utf8_lossy(&output);
    if code != 0 {
        anyhow::bail!("script returned nonzero code {}", code);
    } else {
        Ok(output.into())
    }
}

async fn run_script_args(host: &Host, script: &str, args: Vec<String>) -> anyhow::Result<String> {
    tokio::time::timeout(
        Duration::from_secs(15),
        do_run_script_args(host, script, args),
    )
    .await
    .unwrap_or_else(|_| Err(anyhow::Error::msg("run_script_args timed out")))
}

async fn run_script(host: &Host, script: &str) -> anyhow::Result<String> {
    run_script_args(host, script, vec![]).await
}

async fn run_script_all_args<F: FnMut(&Host) -> Vec<String>>(
    cfg: &Config,
    script: &str,
    mut gen_args: F,
) -> anyhow::Result<JoinSet<(Host, anyhow::Result<String>)>> {
    println!("Executing script on all hosts");
    let mut set = JoinSet::new();
    for (_, host) in cfg.hosts() {
        let host = host.clone();
        let script = script.to_owned();
        let args = gen_args(&host);
        set.spawn(async move { (host.clone(), run_script_args(&host, &script, args).await) });
    }
    Ok(set)
}
async fn run_script_all(
    cfg: &Config,
    script: &str,
) -> anyhow::Result<JoinSet<(Host, anyhow::Result<String>)>> {
    run_script_all_args(cfg, script, |_| vec![]).await
}

pub async fn run(cmd: BlazeCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd {
        BlazeCommand::Scan(cmd) => {
            println!("Subnet: {:?}", cmd.subnet);
            let scan = Scan::new(&cmd.subnet, cmd.backend).await?;
            for host in scan.hosts.iter() {
                println!("{:?}: {:?}", host.addr, host.os);
                let os = host.try_detect_ssh().await;
                match os {
                    Err(err) => println!("{}", err),
                    Ok(os) => println!("Detected OS {:?} from SSH", os),
                }
                cfg.add_host_from(host, cmd.user.clone(), cmd.pass.clone(), cmd.port)?;
            }
        }
        BlazeCommand::Add(cmd) => {
            anyhow::bail!("Not implemented yet");
        }
        BlazeCommand::Password(cmd) => {
            // TODO: Implement
            /*
            let host = lookup_host(cfg, &cmd.host).context("Couldn't find host")?;
            host.pass = cmd.pass;
            */
        }
        BlazeCommand::List => {
            for host in cfg.hosts().values() {
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
            let script = "hostname.sh";
            let mut set = run_script_all(cfg, script).await?;
            while let Some(joined) = set.join_next().await {
                let (mut host, output) = joined.context("Error running hostname script")?;
                match output {
                    Ok(output) => {
                        let alias = output.trim();
                        println!("Got alias {} for host {}", alias, host.ip);
                        host.aliases.insert(alias.into());
                        cfg.add_host(&host);
                    }
                    Err(err) => {
                        println!("Error running script on host {}: {}", host.ip, err);
                    }
                }
            }
        }
        BlazeCommand::Chpass => {
            let script = "chpass.sh";
            let mut passwords = get_passwords()?;
            let mut rng = rand::thread_rng();
            let mut set = run_script_all_args(cfg, script, |host| {
                let rand = rng.gen_range(0..passwords.len());
                let pass = passwords.remove(rand);
                println!("Using password {} for host {}", pass.id, host.ip);
                vec![host.user.clone(), pass.password]
            })
            .await?;
            let mut failed = Vec::<String>::new();
            while let Some(joined) = set.join_next().await {
                let (host, output) = joined.context("Error running password script")?;
                match output {
                    Ok(pass) => {
                        let pass = pass.trim();
                        println!(
                            "Ran password script on host {}, now checking password {}",
                            host.ip, pass
                        );
                        let session =
                            Session::connect(&host.user, pass, (host.ip, host.port)).await;
                        if let Err(err) = session {
                            println!("Password change seems to have failed, error: {}", err);
                            failed.push(format!("{}", host.ip));
                        } else {
                            // TODO: Implement
                            /*
                            println!("Success, writing config file");
                            host.pass = pass.into();
                            */
                            cfg.add_host(&host);
                        }
                    }
                    Err(err) => {
                        println!("Error running script on host {}: {}", host.ip, err);
                        failed.push(format!("{}", host.ip));
                    }
                }
            }
            println!(
                "Total: {} failed password changes (hosts {:?})",
                failed.len(),
                failed.join(" "),
            );
        }
        BlazeCommand::Script(cmd) => match cmd.host {
            Some(host) => {
                let host = lookup_host(&cfg, &host)?;
                println!("Running script on host {}", host.ip);
                let output = run_script(host, &cmd.script).await?;
                println!("Script outputted: {}", output);
            }
            None => {
                let mut set = run_script_all(cfg, &cmd.script).await?;
                while let Some(joined) = set.join_next().await {
                    joined
                        .context("Error running script")
                        .map(|(host, output)| match output {
                            Ok(output) => {
                                println!("Script on host {} outputted: {}", host.ip, output);
                            }
                            Err(err) => {
                                println!("Error running script on host {}: {}", host.ip, err);
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
            let mut session = Session::connect(&host.user, &host.pass, (ip, host.port)).await?;
            let code = session.shell().await?;
            if code != 0 {
                // anyhow::bail!("shell returned nonzero code {}", code);
                println!("Warning: shell returned nonzero code {}", code);
            }
        }
    }
    Ok(())
}
