use crate::config::Config;
use clap::Parser;

mod chpass;
mod config;
mod profile;
mod scan;
mod script;

#[derive(Parser)]
pub enum BlazeCommand {
    Scan(scan::ScanCommand),
    #[clap(alias = "a")]
    Add(config::AddCommand),
    #[clap(alias = "rm")]
    Remove(config::RemoveCommand),
    #[clap(alias = "ls")]
    List(config::ListCommand),
    Timeout(config::TimeoutCommand),
    Export(config::ExportCommand),
    Edit(config::EditCommand),
    #[clap(alias = "r")]
    #[command(about = "Detect the hostnames of all detected hosts.")]
    Resolve,
    #[command(about = "Change the login credentials of all detected hosts.")]
    Chpass,
    #[clap(alias = "sc")]
    Script(script::ScriptCommand),
    #[clap(alias = "sh")]
    Shell(script::ShellCommand),
    Ldap(profile::LdapCommand),
    Rdp,
}

pub async fn run(cmd: BlazeCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd {
        BlazeCommand::Scan(cmd) => scan::scan(cmd, cfg).await?,
        BlazeCommand::Add(cmd) => config::add_host(cmd, cfg).await?,
        BlazeCommand::Remove(cmd) => config::remove_host(cmd, cfg).await?,
        BlazeCommand::List(cmd) => config::list_hosts(cmd, cfg).await?,
        BlazeCommand::Timeout(cmd) => config::set_timeout(cmd, cfg).await?,
        BlazeCommand::Shell(cmd) => script::shell(cmd, cfg).await?,
        BlazeCommand::Export(cmd) => config::export(cmd, cfg).await?,
        BlazeCommand::Resolve => profile::hostname((), cfg).await?,
        BlazeCommand::Chpass => chpass::chpass((), cfg).await?,
        BlazeCommand::Script(cmd) => script::script(cmd, cfg).await?,
        BlazeCommand::Edit(cmd) => config::edit_host(cmd, cfg).await?,
        BlazeCommand::Ldap(cmd) => profile::ldap(cmd, cfg).await?,
        BlazeCommand::Rdp => profile::rdp((), cfg).await?,
    }
    Ok(())
}
