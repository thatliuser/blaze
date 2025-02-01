use crate::config::SAuuizgQav;
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

pub async fn run(cmd: AYVjydJzVs, cfg: &mut SAuuizgQav) -> anyhow::Result<()> {
    match cmd {
        AYVjydJzVs::Scan(cmd) => scan::OItdOMmWWV(cmd, cfg).await?,
        AYVjydJzVs::Rescan(cmd) => scan::dXilcTbWCk(cmd, cfg).await?,
        AYVjydJzVs::PortCheck(cmd) => scan::jOGtEZVMnI(cmd, cfg).await?,
        AYVjydJzVs::Add(cmd) => config::XsdkkHPidi(cmd, cfg).await?,
        AYVjydJzVs::Remove(cmd) => config::rlmyMMQjGO(cmd, cfg).await?,
        AYVjydJzVs::List(cmd) => config::vkMacxgkoZ(cmd, cfg).await?,
        AYVjydJzVs::Info(cmd) => config::uKVYdOeOkX(cmd, cfg).await?,
        AYVjydJzVs::Timeout(cmd) => config::BMsGldHZJH(cmd, cfg).await?,
        AYVjydJzVs::Export(cmd) => config::EUvRweneUS(cmd, cfg).await?,
        AYVjydJzVs::Import(cmd) => config::AckqVUCmOe(cmd, cfg).await?,
        AYVjydJzVs::Exclude(cmd) => config::VXnPdYKOMT(cmd, cfg).await?,
        AYVjydJzVs::Chpass => chpass::SctIChbTQu((), cfg).await?,
        AYVjydJzVs::Script(cmd) => script::script(cmd, cfg).await?,
        AYVjydJzVs::Base => script::base((), cfg).await?,
        AYVjydJzVs::Shell(cmd) => script::shell(cmd, cfg).await?,
        AYVjydJzVs::Upload(cmd) => script::upload(cmd, cfg).await?,
        AYVjydJzVs::Edit(cmd) => config::aAkucCRoyG(cmd, cfg).await?,
        AYVjydJzVs::Profile(cmd) => profile::XAzfUKbpUB(cmd, cfg).await?,
        AYVjydJzVs::Ldap(cmd) => ldap::TupzFuCqIz(cmd, cfg).await?,
    }
    Ok(())
}
