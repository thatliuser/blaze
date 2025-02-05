use crate::crabs::{Crab, CrabResult};
use netstat2::{
    AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, iterate_sockets_info,
};
use serde::Serialize;
use std::net::IpAddr;
use std::path::PathBuf;
use sysinfo::{Pid, System};

pub struct NetstatCrab {}

impl NetstatCrab {
    pub fn full_netstat_output(&self) -> Vec<ListenSocket> {
        let system = System::new_all();
        let sockets = iterate_sockets_info(AddressFamilyFlags::all(), ProtocolFlags::TCP).unwrap();
        sockets
            .filter_map(Result::ok)
            .filter_map(|socket| match &socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                    if tcp.state == TcpState::Listen {
                        Some(socket)
                    } else {
                        None
                    }
                }
                ProtocolSocketInfo::Udp(_) => None,
            })
            .map(|socket| {
                let local_addr = socket.local_addr();
                let local_port = socket.local_port();
                let process = socket
                    .associated_pids
                    .iter()
                    .filter_map(|pid| system.process(Pid::from(*pid as usize)))
                    .next()
                    .map(|process| {
                        let pid = process.pid().as_u32();
                        let name = process.name().to_string_lossy().into_owned();
                        let path = process.exe().map(|path| path.to_owned());
                        let cwd = process.cwd().map(|path| path.to_owned());
                        let cmdline = process
                            .cmd()
                            .iter()
                            .map(|arg| arg.to_string_lossy())
                            .collect::<Vec<_>>()
                            .join(" ");
                        ProcessInfo {
                            pid,
                            name,
                            path,
                            cwd,
                            cmdline,
                        }
                    });
                ListenSocket {
                    local_addr,
                    local_port,
                    process,
                }
            })
            .collect()
    }
}

impl Crab for NetstatCrab {
    fn run(&self) -> CrabResult {
        CrabResult::Netstat(NetstatCrabResult {
            listen_sockets: self.full_netstat_output(),
        })
    }

    fn priority(&self) -> u64 {
        100
    }
}

#[derive(Serialize)]
pub struct NetstatCrabResult {
    pub listen_sockets: Vec<ListenSocket>,
}

#[derive(Serialize)]
pub struct ListenSocket {
    local_addr: IpAddr,
    local_port: u16,
    process: Option<ProcessInfo>,
}

#[derive(Serialize)]
pub struct ProcessInfo {
    pid: u32,
    name: String,
    path: Option<PathBuf>,
    cwd: Option<PathBuf>,
    cmdline: String,
}
