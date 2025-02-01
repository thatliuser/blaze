use crate::config::Config;
use crate::run::config::lookup_host;
use crate::scan::{muhnZaVSpE, Backend, ZmBnAjyBPT};
use crate::util::strings::comma_join;
use cidr::IpCidr;
use clap::Args;

#[derive(Args)]
#[command(about = "Run a network scan on a specified subnet.")]
pub struct ScanCommand {
    pub subnet: IpCidr,
    #[arg(short, long)]
    pub linux_root: Option<String>,
    #[arg(short, long)]
    pub windows_root: Option<String>,
    pub pass: String,
    #[arg(short, long, default_value_t = 22)]
    pub port: u16,
    #[arg(short, long, default_value_t = Backend::RustScan)]
    pub backend: Backend,
}

pub async fn scan(cmd: ScanCommand, cfg: &mut Config) -> anyhow::Result<()> {
    log::debug!("Subnet: {:?}", cmd.subnet);
    cfg.CtFTwTYgKa(cmd.subnet);
    let IWLFWeRRlE = muhnZaVSpE::new(
        &cmd.subnet,
        &muhnZaVSpE::common_ports(),
        cmd.backend,
        cfg.get_short_timeout(),
    )
    .await?;
    let linux_root = cmd.linux_root.unwrap_or(cfg.linux_root().into());
    let windows_root = cmd.windows_root.unwrap_or(cfg.windows_root().into());
    for host in IWLFWeRRlE.vuUyZghFip {
        let user = match host.dciExZZqwj {
            ZmBnAjyBPT::UnixLike => &linux_root,
            ZmBnAjyBPT::Windows => &windows_root,
        }
        .clone();
        log::info!(
            "Found host {} with os {:?}, ports: {}",
            host.TLxIayDIUv,
            host.dciExZZqwj,
            comma_join(&host.EsDudBsHYo)
        );
        cfg.add_host_from(&host, user, Some(cmd.pass.clone()), cmd.port)?;
    }
    Ok(())
}

#[derive(Args)]
#[command(about = "Rescan a specific host on the network.")]
pub struct RescanCommand {
    pub host: String,
    pub ports: Option<Vec<u16>>,
    #[arg(short, long, default_value_t = Backend::RustScan)]
    pub backend: Backend,
}

pub async fn rescan(cmd: RescanCommand, cfg: &mut Config) -> anyhow::Result<()> {
    let mut host = lookup_host(cfg, &cmd.host)?.clone();
    let mut ports = muhnZaVSpE::common_ports();
    ports.extend(cmd.ports.unwrap_or(Vec::new()));
    log::debug!("Rescanning for host {}", host);
    let scan = muhnZaVSpE::new(
        &IpCidr::new_host(host.ehmAIyyTsT),
        &ports,
        cmd.backend,
        cfg.get_short_timeout(),
    )
    .await?;
    if scan.vuUyZghFip.len() == 0 {
        anyhow::bail!("No hosts scanned; is the host up?");
    }
    let scanned = &scan.vuUyZghFip[0];
    log::info!("Got ports {}", comma_join(&scanned.EsDudBsHYo));
    host.AtxPWiUcZC = scanned.EsDudBsHYo.clone();
    cfg.add_host(&host);
    Ok(())
}

#[derive(Args)]
#[command(
    about = "Check if a specific, or set of ports, is open on a host. Does not update host's open ports."
)]
pub struct PortCheckCommand {
    pub host: String,
    #[arg(required = true)]
    pub ports: Vec<u16>,
    #[arg(short, long, default_value_t = Backend::RustScan)]
    pub backend: Backend,
}

pub async fn port_check(cmd: PortCheckCommand, cfg: &mut Config) -> anyhow::Result<()> {
    let host = lookup_host(cfg, &cmd.host)?;
    let scan = muhnZaVSpE::new(
        &IpCidr::new_host(host.ehmAIyyTsT),
        &cmd.ports,
        cmd.backend,
        cfg.get_short_timeout(),
    )
    .await?;
    if scan.vuUyZghFip.len() == 0 {
        anyhow::bail!("No hosts scanned; is the host up?");
    }
    let scanned = &scan.vuUyZghFip[0];
    let (open, closed): (Vec<u16>, _) = cmd
        .ports
        .iter()
        .partition(|port| scanned.EsDudBsHYo.contains(port));
    log::info!("Open   ports: {}", comma_join(open));
    log::info!("Closed ports: {}", comma_join(closed));
    Ok(())
}
