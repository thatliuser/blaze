// Entrypoint

mod config;
mod nmap;
mod ssh;

use clap::{Args, Parser};
use config::Config;
use ssh::Session;
use std::{net::IpAddr, path::PathBuf};

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
    Resolve(ResolveCommand),
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
#[command(about = "Detect the hostnames of all detected hosts.")]
struct ResolveCommand {}

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
            Ok(())
        }
        BlazeCommand::Add(cmd) => {
            anyhow::bail!("Not implemented yet");
        }
        BlazeCommand::List => {
            for host in cfg.hosts().values() {
                println!("{:?}", host);
            }
            Ok(())
        }
        BlazeCommand::Resolve(cmd) => {
            anyhow::bail!("Not implemented yet");
        }
        BlazeCommand::Script(cmd) => {
            println!("Executing script {} on {}", cmd.script.display(), cmd.host);
            let ip = cmd.host.parse()?;
            let host = cfg
                .host_for_ip(ip)
                .ok_or_else(|| anyhow::Error::msg("Failed to get host for IP"))?;
            let mut session =
                Session::connect(host.user.clone(), host.pass.clone(), (ip, host.port)).await?;
            let (code, output) = session.run_script(cmd.script.into_os_string().into_string().unwrap(), false).await?;
            println!("Program returned code {}", code);
            println!("Output: {}", String::from_utf8_lossy(&output));
            Ok(())
        }
        BlazeCommand::Shell(cmd) => {
            println!("Host: {}", cmd.host);
            anyhow::bail!("Not implemented yet");
        }
    }
}
