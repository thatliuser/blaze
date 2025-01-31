use crate::config::Config;
use crate::scan::{Backend, OsType, Scan};
use cidr::IpCidr;
use clap::Args;

use super::config::lookup_host;

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
    let scan = Scan::new(
        &cmd.subnet,
        &Scan::common_ports(),
        cmd.backend,
        cfg.get_short_timeout(),
    )
    .await?;
    for host in scan.hosts {
        let user = match host.os {
            OsType::UnixLike => &cmd.linux_root,
            OsType::Windows => &cmd.windows_root,
        }
        .clone();
        log::info!(
            "Found host {} with os {:?}, ports: {}",
            host.addr,
            host.os,
            host.ports
                .iter()
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        cfg.add_host_from(&host, user, Some(cmd.pass.clone()), cmd.port)?;
    }
    Ok(())
}

#[derive(Args)]
#[command(
    about = "Rescan a specific host on the network. If you specify ports, the open host ports will not be edited."
)]
pub struct RescanCommand {
    pub host: String,
    pub ports: Option<Vec<u16>>,
    #[arg(short, long, default_value_t = Backend::RustScan)]
    pub backend: Backend,
    #[arg(short, long, default_value_t = true)]
    pub quick: bool,
}

pub async fn rescan(cmd: RescanCommand, cfg: &mut Config) -> anyhow::Result<()> {
    let mut host = lookup_host(cfg, &cmd.host)?.clone();
    let edit_host = cmd.ports.is_none();
    let ports = cmd.ports.unwrap_or(Scan::common_ports());
    log::debug!("Rescanning for host {}", host);
    let scan = Scan::new(
        &IpCidr::new_host(host.ip),
        &ports,
        cmd.backend,
        cfg.get_short_timeout(),
    )
    .await?;
    if scan.hosts.len() == 0 {
        anyhow::bail!("No hosts scanned; is the host up?");
    }
    let scanned = &scan.hosts[0];
    log::info!(
        "Got ports {}",
        scanned
            .ports
            .iter()
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if edit_host {
        host.open_ports = scanned.ports.clone();
        cfg.add_host(&host);
    }
    Ok(())
}
