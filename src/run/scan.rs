use crate::config::Config;
use crate::scan::{Backend, Scan};
use anyhow::Context;
use cidr::IpCidr;
use clap::Args;
use tokio::task::JoinSet;

#[derive(Args)]
#[command(about = "Run a network scan on a specified subnet.")]
pub struct ScanCommand {
    pub subnet: IpCidr,
    #[arg(short, long, default_value_t = String::from("root"))]
    pub linux_root: String,
    #[arg(short, long, default_value_t = String::from("Administrator"))]
    pub windows_root: String,
    pub pass: String,
    #[arg(short, long, default_value_t = 22)]
    pub port: u16,
    #[arg(short, long, default_value_t = Backend::RustScan)]
    pub backend: Backend,
}

pub async fn scan(cmd: ScanCommand, cfg: &mut Config) -> anyhow::Result<()> {
    log::debug!("Subnet: {:?}", cmd.subnet);
    cfg.set_cidr(cmd.subnet);
    let scan = Scan::new(&cmd.subnet, cmd.backend).await?;
    let mut set = JoinSet::new();
    for host in scan.hosts.iter() {
        log::info!("Got host {} with OS {:?}", host.addr, host.os);
        let host = host.clone();
        let timeout = cfg.get_timeout();
        set.spawn(async move { (host.clone(), host.try_detect_ssh(timeout).await) });
    }
    while let Some(joined) = set.join_next().await {
        let (mut host, result) = joined.context("Failed to spawn host ID detector")?;
        match result {
            Ok((id, os)) => {
                if os != host.os {
                    log::info!(
                        "Host {} OS changed from {:?} to {:?} (SSH ID {})",
                        host.addr,
                        host.os,
                        os,
                        id
                    );
                    host.os = os;
                }
            }
            Err(err) => {
                log::error!("Failed to detect host {} ID from SSH: {}", host.addr, err);
            }
        }
        cfg.add_host_from(
            &host,
            cmd.linux_root.clone(),
            Some(cmd.pass.clone()),
            cmd.port,
        )?;
    }
    Ok(())
}
