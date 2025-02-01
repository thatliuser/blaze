use crate::config::Config;
use crate::proto::ldap::Session;
use crate::run::config::lookup_host;
use anyhow::Context;
use clap::{Args, Subcommand};
use ldap3::SearchEntry;

#[derive(Args)]
#[command(about = "Test or lookup LDAP.")]
pub struct LdapCommand {
    pub host: String,
    #[arg(short, long, default_value = None)]
    pub user: Option<String>,
    #[arg(short, long, default_value = None)]
    pub pass: Option<String>,
    #[arg(short, long, default_value = None)]
    pub domain: Option<String>,
    #[command(subcommand)]
    pub cmd: LdapCommandEnum,
}

#[derive(Subcommand)]
pub enum LdapCommandEnum {
    Test,
    Users,
    Search(SearchCommand),
}

pub async fn ldap(cmd: LdapCommand, cfg: &mut Config) -> anyhow::Result<()> {
    let host = lookup_host(cfg, &cmd.host)?;
    let domain = cmd
        .domain
        .or_else(|| {
            host.aliases
                .iter()
                .map(|alias| alias.splitn(2, ".").collect::<Vec<_>>())
                .filter_map(|alias| {
                    if alias.len() == 2 {
                        Some(alias[1].to_owned())
                    } else {
                        None
                    }
                })
                .next()
        })
        .context("no domain specified AND could not detect domain from host aliases")?;
    let user = cmd.user.as_ref().unwrap_or_else(|| &host.user);
    let pass: &str = cmd
        .pass
        .as_ref()
        .or_else(|| host.pass.as_ref())
        .context("no pass specified AND host does not have a password set")?;
    let session = tokio::time::timeout(
        cfg.get_short_timeout(),
        Session::new(host.ip, &domain, user, pass),
    )
    .await
    .context("ldap connection timed out")?
    .context("ldap connection failed")?;
    match cmd.cmd {
        // Already connected so already tested
        LdapCommandEnum::Test => {
            log::info!("LDAP connection succeeded, leaving");
            Ok(())
        }
        LdapCommandEnum::Users => users(session).await,
        LdapCommandEnum::Search(cmd) => search(cmd, session).await,
    }
}

async fn users(mut session: Session) -> anyhow::Result<()> {
    let users = session.users().await?;
    let (admins, users): (Vec<_>, _) = users.into_iter().partition(|user| user.admin);
    log::info!("Admins for {}:", session.domain());
    for admin in admins {
        println!("{:<25} (full name {})", admin.id, admin.name);
    }
    log::info!("Users for {}:", session.domain());
    for user in users {
        println!("{:<25} (full name {})", user.id, user.name);
    }
    Ok(())
}

#[derive(Args)]
#[command(about = "Search a specific container in LDAP.")]
pub struct SearchCommand {
    pub container: String,
    #[arg(default_value = "(objectClass=top)")]
    pub filter: String,
    #[arg(default_values_t = ["*".to_string()])]
    pub attrs: Vec<String>,
}

async fn search(cmd: SearchCommand, mut session: Session) -> anyhow::Result<()> {
    let entries = session
        .search(&cmd.container, &cmd.filter, cmd.attrs)
        .await?;

    for entry in entries {
        let entry = SearchEntry::construct(entry);
        println!("dn: {}", entry.dn);
        for (key, vals) in entry.attrs {
            for val in vals {
                println!("{}: {}", key, val);
            }
        }
        // Separator
        println!("");
    }

    Ok(())
}
