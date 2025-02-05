use std::{collections::HashMap, net::SocketAddr};

use crate::crabs::{Crab, CrabResult};
use bollard::{Docker, container::ListContainersOptions};
use serde::Serialize;
use tokio::runtime::Runtime;

pub struct ContainerCrab {}

async fn get_container_info() -> anyhow::Result<Vec<ContainerInfo>> {
    let conn = Docker::connect_with_local_defaults()?;
    let opts = Some(ListContainersOptions::<String>::default());
    let mut info = vec![];
    for container in conn.list_containers(opts).await? {
        let container_id = container.id;
        let container_names = container.names;
        let image = container.image;
        let command = container.command;
        let port_bindings = container.ports.map(|ports| {
            ports
                .iter()
                .filter_map(|port| {
                    let priv_port = port.private_port;
                    let pub_port = port.public_port?;
                    let ip = port.ip.clone()?;
                    let addr = format!("{}:{}", ip, pub_port);
                    Some((priv_port, addr))
                })
                .collect()
        });
        info.push(ContainerInfo {
            container_id,
            container_names,
            image,
            command,
            port_bindings,
        })
    }
    Ok(info)
}

impl Crab for ContainerCrab {
    fn run(&self) -> CrabResult {
        let containers = Runtime::new()
            .map(|runtime| {
                runtime
                    .block_on(get_container_info())
                    .unwrap_or_else(|_| Vec::new())
            })
            .unwrap_or_else(|_| Vec::new());
        CrabResult::Container(ContainerCrabResult { containers })
    }
    fn priority(&self) -> u64 {
        70
    }
}

#[derive(Serialize)]
pub struct ContainerCrabResult {
    pub containers: Vec<ContainerInfo>,
}

#[derive(Serialize)]
pub struct ContainerInfo {
    pub container_id: Option<String>,
    pub container_names: Option<Vec<String>>,
    pub image: Option<String>,
    pub command: Option<String>,
    pub port_bindings: Option<Vec<(u16, String)>>,
}
