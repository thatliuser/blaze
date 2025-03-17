use crate::config::Config;
use crate::proto::ssh::Session;
use crate::run::script::{run_script_all_args, RunScriptArgs};
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
    let mut reader = csv::Reader::from_path("passwords.db")
        .context("couldn't open password file - have you run passgen yet?")?;
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
        cfg.get_long_timeout(),
        cfg,
        |host| {
            let rand = rng.gen_range(0..passwords.len());
            let pass = passwords.remove(rand);
            log::info!("Using password {} for host {}", pass.id, host);
            vec![host.user.clone(), pass.password]
        },
        RunScriptArgs::new(script),
    )
    .await;
    let mut failed = Vec::<(String, String)>::new();
    while let Some(joined) = set.join_next().await {
        let (mut host, output) = joined.context("Error running password script")?;
        match output {
            Ok((code, pass)) => {
                if code != 0 {
                    log::trace!(
                        "Password script returned nonzero code {} for host {}",
                        code,
                        host
                    );
                }
                let pass = pass.trim();
                log::trace!(
                    "Ran password script on host {}, now checking password {}",
                    host,
                    pass
                );
                let session = Session::connect(&host.user, pass, (host.ip, host.port)).await;
                if let Err(err) = session {
                    log::trace!("Password change seems to have failed, error: {}", err);
                    failed.push((host.to_string(), err.to_string()));
                } else {
                    log::trace!("Success, writing config file");
                    host.pass = Some(pass.into());
                    cfg.add_host(&host);
                }
            }
            Err(err) => {
                log::trace!("Error running script on host {}: {}", host, err);
                failed.push((host.to_string(), err.to_string()));
            }
        }
    }
    log::info!("Total: {} failed password changes", failed.len(),);
    for (host, error) in failed {
        log::info!("Host {}: {}", host, error);
    }
    Ok(())
}
