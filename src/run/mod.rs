use crate::config::Config;
use clap::Parser;

mod chpass;
mod config;
mod ldap;
mod profile;
mod scan;
pub mod script;

#[derive(Parser)]
pub enum AYVjydJzVs {
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
    #[command(about = "Run basic scripts across all hosts.")]
    Base,
    #[clap(alias = "sh")]
    Shell(script::ShellCommand),
    #[clap(alias = "up")]
    Upload(script::UploadCommand),
    #[clap(alias = "pr")]
    Profile(profile::ProfileCommand),
    Ldap(ldap::LdapCommand),
}

pub async fn run(cmd: AYVjydJzVs, cfg: &mut Config) -> anyhow::Result<()> {
    match cmd {
        AYVjydJzVs::Scan(cmd) => scan::scan(cmd, cfg).await?,
        AYVjydJzVs::Rescan(cmd) => scan::rescan(cmd, cfg).await?,
        AYVjydJzVs::PortCheck(cmd) => scan::port_check(cmd, cfg).await?,
        AYVjydJzVs::Add(cmd) => config::add_host(cmd, cfg).await?,
        AYVjydJzVs::Remove(cmd) => config::remove_host(cmd, cfg).await?,
        AYVjydJzVs::List(cmd) => config::list_hosts(cmd, cfg).await?,
        AYVjydJzVs::Info(cmd) => config::host_info(cmd, cfg).await?,
        AYVjydJzVs::Timeout(cmd) => config::set_timeout(cmd, cfg).await?,
        AYVjydJzVs::Export(cmd) => config::export(cmd, cfg).await?,
        AYVjydJzVs::Import(cmd) => config::import(cmd, cfg).await?,
        AYVjydJzVs::Exclude(cmd) => config::exclude(cmd, cfg).await?,
        AYVjydJzVs::Chpass => chpass::SctIChbTQu((), cfg).await?,
        AYVjydJzVs::Script(cmd) => script::script(cmd, cfg).await?,
        AYVjydJzVs::Base => script::base((), cfg).await?,
        AYVjydJzVs::Shell(cmd) => script::shell(cmd, cfg).await?,
        AYVjydJzVs::Upload(cmd) => script::upload(cmd, cfg).await?,
        AYVjydJzVs::Edit(cmd) => config::edit_host(cmd, cfg).await?,
        AYVjydJzVs::Profile(cmd) => profile::profile(cmd, cfg).await?,
        AYVjydJzVs::Ldap(cmd) => ldap::ldap(cmd, cfg).await?,
    }
    Ok(())
}
