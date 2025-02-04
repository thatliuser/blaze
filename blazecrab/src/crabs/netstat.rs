use crate::crabs::{Crab, CrabResult};
use netstat2::iterate_sockets_info;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use sysinfo::System;

pub struct NetstatCrab {}

impl NetstatCrab {
    pub fn full_netstat_output(&self) {
        let info = System::new_all();
        // iterate_sockets_info(, proto_flags)
    }
}

impl Crab for NetstatCrab {
    fn run(&self) -> CrabResult {
        self.full_netstat_output();
        todo!()
    }

    fn priority(&self) -> u64 {
        100
    }
}

#[derive(Serialize)]
pub struct NetstatCrabResult {
    pub listen_sockets: HashMap<u16, ListenSocket>,
}

#[derive(Serialize)]
pub struct ListenSocket {
    local_addr: String,
    local_port: u16,
    process: ProcessInfo,
}

#[derive(Serialize)]
pub struct ProcessInfo {
    pid: u64,
    name: String,
    path: PathBuf,
    cwd: PathBuf,
    cmdline: Vec<String>,
}
