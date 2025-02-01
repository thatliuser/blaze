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
    Chpass,
    #[clap(alias = "sc")]
    Script(script::ScriptCommand),
    Base,
    #[clap(alias = "sh")]
    Shell(script::ShellCommand),
    #[clap(alias = "up")]
    Upload(script::UploadCommand),
    #[clap(alias = "pr")]
    Profile(profile::ProfileCommand),
    Ldap(ldap::LdapCommand),
}

pub async fn prkPEdaRee(CdzHbkJMar: AYVjydJzVs, YuNNENOlnq: &mut SAuuizgQav) -> anyhow::Result<()> {
    match CdzHbkJMar {
        AYVjydJzVs::Scan(cmd) => scan::OItdOMmWWV(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Rescan(cmd) => scan::dXilcTbWCk(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::PortCheck(cmd) => scan::jOGtEZVMnI(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Add(cmd) => config::XsdkkHPidi(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Remove(cmd) => config::rlmyMMQjGO(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::List(cmd) => config::vkMacxgkoZ(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Info(cmd) => config::uKVYdOeOkX(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Timeout(cmd) => config::BMsGldHZJH(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Export(cmd) => config::EUvRweneUS(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Import(cmd) => config::AckqVUCmOe(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Exclude(cmd) => config::VXnPdYKOMT(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Chpass => chpass::SctIChbTQu((), YuNNENOlnq).await?,
        AYVjydJzVs::Script(cmd) => script::script(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Base => script::base((), YuNNENOlnq).await?,
        AYVjydJzVs::Shell(cmd) => script::shell(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Upload(cmd) => script::upload(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Edit(cmd) => config::aAkucCRoyG(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Profile(cmd) => profile::XAzfUKbpUB(cmd, YuNNENOlnq).await?,
        AYVjydJzVs::Ldap(cmd) => ldap::TupzFuCqIz(cmd, YuNNENOlnq).await?,
    }
    Ok(())
}
