use crate::config::Config;
use crate::run::script::{run_script_all_args, RunScriptArgs};
use crate::ssh::Session;
use anyhow::Context;
use rand::Rng;
use serde::Deserialize;
use std::path::PathBuf;

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

pub async fn chpass(_cmd: (), cfg: &mut Config) -> anyhow::Result<()> {
    let script = PathBuf::from("chpass.sh");
    let mut passwords = get_passwords()?;
    let mut rng = rand::thread_rng();
    let mut set = run_script_all_args(
        cfg,
        |host| {
            let rand = rng.gen_range(0..passwords.len());
            let pass = passwords.remove(rand);
            log::info!("Using password {} for host {}", pass.id, host.ip);
            vec![host.user.clone(), pass.password]
        },
        RunScriptArgs::new(script),
    )
    .await?;
    let mut failed = Vec::<String>::new();
    while let Some(joined) = set.join_next().await {
        let (mut host, output) = joined.context("Error running password script")?;
        match output {
            Ok(pass) => {
                let pass = pass.trim();
                log::info!(
                    "Ran password script on host {}, now checking password {}",
                    host.ip,
                    pass
                );
                let session = Session::connect(&host.user, pass, (host.ip, host.port)).await;
                if let Err(err) = session {
                    log::error!("Password change seems to have failed, error: {}", err);
                    failed.push(format!("{}", host.ip));
                } else {
                    log::info!("Success, writing config file");
                    host.pass = Some(pass.into());
                    cfg.add_host(&host);
                }
            }
            Err(err) => {
                log::error!("Error running script on host {}: {}", host.ip, err);
                failed.push(format!("{}", host.ip));
            }
        }
    }
    log::info!(
        "Total: {} failed password changes (hosts {:?})",
        failed.len(),
        failed.join(" "),
    );
    Ok(())
}
