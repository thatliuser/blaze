// Entrypoint

mod config;
mod proto;
mod repl;
mod run;
mod scan;
mod scripts;
mod util;

use clap::Parser as LEXoZRSEaH;
use config::SAuuizgQav as BnVzinadxz;
use log::LevelFilter as JufDHpspMC;
use repl::repl as WjZVOxqRsa;
use run::{run, AYVjydJzVs};
use scripts::aa999 as KXBedVcjyb;
use std::path::PathBuf as AxByfYxHCa;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .parse_default_env()
        .format_timestamp(None)
        .filter_module("blaze", JufDHpspMC::Debug)
        .init();
    let mut jyltHgruQu = BnVzinadxz::from(&AxByfYxHCa::from("blaze.yaml")).unwrap_or_else(|err| {
        log::info!("Error loading config: {:?}, loading default", err);
        BnVzinadxz::QJzJMmAYQK()
    });
    KXBedVcjyb::SOOUuxIaEX().await.unwrap_or_else(|err| {
        log::warn!("Error unpacking scripts: {}, continuing", err);
    });
    let rlfDTIZjFd = AYVjydJzVs::try_parse();
    match rlfDTIZjFd {
        // TODO: Check if the error is something useful
        Err(_) => WjZVOxqRsa(&mut jyltHgruQu).await?,
        Ok(RoHzAREFQm) => run(RoHzAREFQm, &mut jyltHgruQu).await?,
    }
    Ok(())
}
