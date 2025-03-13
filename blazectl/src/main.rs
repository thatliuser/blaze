// Entrypoint

mod config;
mod proto;
mod repl;
mod run;
mod scan;
mod scripts;
mod util;

use clap::{error::ErrorKind, Parser};
use config::Config;
use log::LevelFilter;
use repl::repl;
use run::{run_cli, CliCommand};
use rustls::crypto::aws_lc_rs::default_provider;
use scripts::Scripts;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .parse_default_env()
        .format_timestamp(None)
        .filter_module("blaze", LevelFilter::Debug)
        .init();
    default_provider()
        .install_default()
        .map_err(|_| anyhow::Error::msg("Failed to initialize rustls"))?;
    let mut cfg = Config::from(&PathBuf::from("blaze.yaml")).unwrap_or_else(|err| {
        log::info!("Error loading config: {:?}, loading default", err);
        Config::new()
    });
    Scripts::unpack().await.unwrap_or_else(|err| {
        log::warn!("Error unpacking scripts: {}, continuing", err);
    });
    let command = CliCommand::try_parse();
    match command {
        Err(err) => println!("{}", err),
        Ok(command) => run_cli(command, &mut cfg).await?,
    }
    Ok(())
}
