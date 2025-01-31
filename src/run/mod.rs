use crate::config::Config;
use clap::Parser;

mod chpass;
mod config;
mod profile;
mod scan;
pub mod script;

#[derive(Parser)]
pub enum BlazeCommand {
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
    #[clap(alias = "r")]
    #[command(about = "Change the login credentials of all detected hosts.")]
    Chpass,
    #[clap(alias = "sc")]
    Script(script::ScriptCommand),
    #[clap(alias = "sh")]
    Shell(script::ShellCommand),
    #[clap(alias = "up")]
    Upload(script::UploadCommand),
    #[clap(alias = "pr")]
    Profile(profile::ProfileCommand),
}

pub async fn run(cmd: BlazeCommand, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd {
        BlazeCommand::Scan(cmd) => scan::scan(cmd, cfg).await?,
        BlazeCommand::Rescan(cmd) => scan::rescan(cmd, cfg).await?,
        BlazeCommand::PortCheck(cmd) => scan::port_check(cmd, cfg).await?,
        BlazeCommand::Add(cmd) => config::add_host(cmd, cfg).await?,
        BlazeCommand::Remove(cmd) => config::remove_host(cmd, cfg).await?,
        BlazeCommand::List(cmd) => config::list_hosts(cmd, cfg).await?,
        BlazeCommand::Info(cmd) => config::host_info(cmd, cfg).await?,
        BlazeCommand::Timeout(cmd) => config::set_timeout(cmd, cfg).await?,
        BlazeCommand::Export(cmd) => config::export(cmd, cfg).await?,
        BlazeCommand::Import(cmd) => config::import(cmd, cfg).await?,
        BlazeCommand::Exclude(cmd) => config::exclude(cmd, cfg).await?,
        BlazeCommand::Chpass => chpass::chpass((), cfg).await?,
        BlazeCommand::Script(cmd) => script::script(cmd, cfg).await?,
        BlazeCommand::Shell(cmd) => script::shell(cmd, cfg).await?,
        BlazeCommand::Upload(cmd) => script::upload(cmd, cfg).await?,
        BlazeCommand::Edit(cmd) => config::edit_host(cmd, cfg).await?,
        BlazeCommand::Profile(cmd) => profile::profile(cmd, cfg).await?,
    }
    Ok(())
}
