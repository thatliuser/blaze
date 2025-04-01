use crate::{config::Config, repl};
use clap::Parser;

mod config;
mod ldap;
mod pass;
mod profile;
mod scan;
pub mod script;

#[derive(Parser)]
pub enum ReplCommand {
    #[command(about = "Exit REPL.")]
    Exit,
    #[command(flatten)]
    Other(CoreCommand),
}

#[derive(Parser)]
pub enum CliCommand {
    #[command(about = "Start a REPL.")]
    Repl,
    #[command(flatten)]
    Other(CoreCommand),
}

// Commands that are allowed to be run within the REPL
#[derive(Parser)]
pub enum CoreCommand {
    Scan(scan::ScanCommand),
    Rescan(scan::RescanCommand),
    #[clap(alias = "pc")]
    PortCheck(scan::PortCheckCommand),
    #[clap(alias = "a")]
    Add(config::AddCommand),
    #[clap(alias = "rm")]
    Remove(config::RemoveCommand),
    #[clap(alias = "ls")]
    List(config::ListCommand),
    #[clap(alias = "i")]
    Info(config::InfoCommand),
    #[clap(alias = "tm")]
    Timeout(config::TimeoutCommand),
    Export(config::ExportCommand),
    Import(config::ImportCommand),
    #[clap(alias = "e")]
    Edit(config::EditCommand),
    Exclude(config::ExcludeCommand),
    #[clap(alias = "pw")]
    #[command(subcommand)]
    Pass(pass::PassCommand),
    #[clap(alias = "sc")]
    Script(script::ScriptCommand),
    Base(script::BaseCommand),
    #[clap(alias = "sh")]
    Shell(script::ShellCommand),
    #[clap(alias = "up")]
    Upload(script::UploadCommand),
    #[clap(alias = "pr")]
    Profile(profile::ProfileCommand),
    Ldap(ldap::LdapCommand),
}

pub async fn run_core(cmd: CoreCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd {
        CoreCommand::Scan(cmd) => scan::scan(cmd, cfg).await?,
        CoreCommand::Rescan(cmd) => scan::rescan(cmd, cfg).await?,
        CoreCommand::PortCheck(cmd) => scan::port_check(cmd, cfg).await?,
        CoreCommand::Add(cmd) => config::add_host(cmd, cfg).await?,
        CoreCommand::Remove(cmd) => config::remove_host(cmd, cfg).await?,
        CoreCommand::List(cmd) => config::list_hosts(cmd, cfg).await?,
        CoreCommand::Info(cmd) => config::host_info(cmd, cfg).await?,
        CoreCommand::Timeout(cmd) => config::set_timeout(cmd, cfg).await?,
        CoreCommand::Export(cmd) => config::export(cmd, cfg).await?,
        CoreCommand::Import(cmd) => config::import(cmd, cfg).await?,
        CoreCommand::Exclude(cmd) => config::exclude(cmd, cfg).await?,
        CoreCommand::Pass(cmd) => pass::pass(cmd, cfg).await?,
        CoreCommand::Script(cmd) => script::script(cmd, cfg).await?,
        CoreCommand::Base(cmd) => script::base(cmd, cfg).await?,
        CoreCommand::Shell(cmd) => script::shell(cmd, cfg).await?,
        CoreCommand::Upload(cmd) => script::upload(cmd, cfg).await?,
        CoreCommand::Edit(cmd) => config::edit_host(cmd, cfg).await?,
        CoreCommand::Profile(cmd) => profile::profile(cmd, cfg).await?,
        CoreCommand::Ldap(cmd) => ldap::ldap(cmd, cfg).await?,
    }
    Ok(())
}

pub async fn run_cli(cmd: CliCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd {
        CliCommand::Repl => repl::repl(cfg).await?,
        CliCommand::Other(cmd) => run_core(cmd, cfg).await?,
    }
    Ok(())
}
