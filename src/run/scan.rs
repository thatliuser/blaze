use crate::config::Config;
use crate::scan::{Backend, OsType, Scan};
use cidr::IpCidr;
use clap::Args;

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
    for host in scan.hosts {
        let user = match host.os {
            OsType::UnixLike => &cmd.linux_root,
            OsType::Windows => &cmd.windows_root,
        }
        .clone();
        log::info!("Found host {} with os {:?}", host.addr, host.os);
        cfg.add_host_from(&host, user, Some(cmd.pass.clone()), cmd.port)?;
    }
    Ok(())
}
