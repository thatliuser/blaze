use clap::{Args, Parser};
use std::path::Path;

mod nmap;

#[derive(Parser)]
enum BlazeCommand {
    #[clap(alias = "n")]
    Scan(ScanCommand),
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
}

#[derive(Args)]
#[command(about = "Detect the hostnames of all detected hosts.")]
struct ResolveCommand {}

#[derive(Args)]
#[command(about = "Run a script on all detected hosts.")]
struct ScriptCommand {
    pub host: String,
    pub script: Box<Path>,
}

#[derive(Args)]
#[command(about = "Start an augmented remote shell to a specified host.")]
struct ShellCommand {
    pub host: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match BlazeCommand::parse() {
        BlazeCommand::Scan(cmd) => {
            println!("Subnet: {}", cmd.subnet);
            let scan = nmap::Scan::new(cmd.subnet)?;
            let hosts = scan.get_categorized_hosts();
            for host in hosts.iter() {
                println!("{:?}: {:?}", host.host.addresses(), host.os);
            }
            Ok(())
        }
        BlazeCommand::Resolve(cmd) => {
            anyhow::bail!("Not implemented yet");
        }
        BlazeCommand::Script(cmd) => {
            println!("Executing script {} on {}", cmd.script.display(), cmd.host);
            anyhow::bail!("Not implemented yet");
        }
        BlazeCommand::Shell(cmd) => {
            println!("Host: {}", cmd.host);
            anyhow::bail!("Not implemented yet");
        }
    }
}
