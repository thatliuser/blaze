use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Duration,
};

use cidr::IpCidr;
use serde::{Deserialize, Serialize};
// This is mostly mirrored from the SQL file in the migrations directory.
// Sensitive data is not given.
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum OsType {
    Windows,
    Linux,
    Other,
}

#[derive(Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize)]
pub struct Host {
    pub cidr: IpCidr,
    pub ip: IpAddr,
    pub aliases: HashSet<String>,
    pub ports: HashSet<u16>,
    pub services: HashMap<String, Service>,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub os: OsType,
}

struct DbHost {
    pub cidr: String,
    pub ip: String,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub os: String,
}

impl Host {
    async fn host_from_tables(host: &DbHost, pool: &sqlx::SqlitePool) -> anyhow::Result<Self> {
        let aliases = sqlx::query!(
            "SELECT alias FROM HostAliases WHERE cidr = ? AND ip = ?",
            host.cidr,
            host.ip
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|alias| alias.alias)
        .collect();
        let services = sqlx::query!(
            r#"SELECT name, port as "port: u16" FROM Services WHERE cidr = ? AND ip = ?"#,
            host.cidr,
            host.ip
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|service| {
            (service.name.clone(), Service {
                name: service.name,
                port: service.port,
            })
        })
        .collect();
        let ports = sqlx::query!(
            r#"SELECT port as "port: u16" FROM HostPorts WHERE cidr = ? AND ip = ?"#,
            host.cidr,
            host.ip
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|port| port.port)
        .collect();
        let cidr: IpCidr = host.cidr.parse()?;
        Ok(Self {
            cidr,
            ip: host.ip.parse()?,
            aliases: aliases,
            ports: ports,
            services: services,
            user: host.user.clone(),
            pass: host.pass.clone(),
            // TODO: Fix with strum or smth
            os: OsType::Other,
        })
    }
    pub async fn hosts_for_network(
        pool: &sqlx::SqlitePool,
        network: &Network,
    ) -> anyhow::Result<Vec<Self>> {
        let mut hosts = vec![];
        let cidr = network.cidr.to_string();
        for host in sqlx::query_as!(DbHost, "SELECT * FROM Hosts WHERE cidr = ?", cidr)
            .fetch_all(pool)
            .await?
        {
            hosts.push(Self::host_from_tables(&host, pool).await?);
        }
        Ok(hosts)
    }
    pub async fn insert(&self, network: &Network, pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
        let cidr = network.cidr.to_string();
        let ip = self.ip.to_string();
        for port in self.ports.iter() {
            sqlx::query!(
                "INSERT INTO HostPorts (cidr, ip, port) VALUES (?, ?, ?)",
                cidr,
                ip,
                port
            )
            .execute(pool)
            .await?;
        }
        for alias in self.aliases.iter() {
            sqlx::query!(
                "INSERT INTO HostAliases (cidr, ip, alias) VALUES (?, ?, ?)",
                cidr,
                ip,
                alias
            )
            .execute(pool)
            .await?;
        }
        sqlx::query!(
            "INSERT INTO Hosts (cidr, ip, user, pass, os) VALUES (?, ?, ?, ?, ?)",
            cidr,
            ip,
            self.user,
            self.pass,
            // TODO: Fix OS thing
            ""
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Network {
    pub cidr: IpCidr,
    pub short_timeout: Duration,
    pub long_timeout: Duration,
    pub linux_root: String,
    pub windows_root: String,
    pub default_pass: String,
    pub ignored_hosts: HashSet<IpAddr>,
}

struct DbNetwork {
    pub cidr: String,
    pub short_timeout_ms: i64,
    pub long_timeout_ms: i64,
    pub linux_root_user: String,
    pub windows_root_user: String,
    pub default_pass: String,
}

impl Network {
    pub async fn insert(&self, pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
        let cidr = self.cidr.to_string();
        let short_timeout_ms: i64 = self.short_timeout.as_millis().try_into()?;
        let long_timeout_ms: i64 = self.long_timeout.as_millis().try_into()?;
        sqlx::query!(
            "INSERT INTO Networks (cidr, short_timeout_ms, long_timeout_ms, linux_root_user, windows_root_user, default_pass) VALUES (?, ?, ?, ?, ?, ?)",
            cidr,
            short_timeout_ms,
            long_timeout_ms,
            self.linux_root,
            self.windows_root,
            self.default_pass
        )
        .execute(pool)
        .await?;
        Ok(())
    }
    pub async fn all(pool: &sqlx::SqlitePool) -> anyhow::Result<Vec<Self>> {
        let mut networks = vec![];
        for network in sqlx::query_as!(DbNetwork, "SELECT * FROM Networks")
            .fetch_all(pool)
            .await?
        {
            let ignored_hosts = sqlx::query!(
                "SELECT ip FROM NetworkIgnoredHosts WHERE cidr = ?",
                network.cidr
            )
            .fetch_all(pool)
            .await?
            .into_iter()
            .filter_map(|excluded| excluded.ip.parse().ok())
            .collect();
            networks.push(Self {
                cidr: network.cidr.parse()?,
                short_timeout: Duration::from_millis(network.short_timeout_ms.try_into()?),
                long_timeout: Duration::from_millis(network.long_timeout_ms.try_into()?),
                linux_root: network.linux_root_user,
                windows_root: network.windows_root_user,
                default_pass: network.default_pass,
                ignored_hosts,
            })
        }
        Ok(networks)
    }
}
