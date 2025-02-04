use crate::crabs::{Crab, CrabResult};
use serde::Serialize;
use sysinfo::System;

pub struct HostCrab {}

// TODO: Check if Option<> is correct here
#[derive(Serialize)]
pub struct HostCrabResult {
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub hostname: Option<String>,
    pub distribution: String,
    pub arch: String,
    pub container_runtime: Option<String>,
}

impl Crab for HostCrab {
    fn run(&self) -> CrabResult {
        let os = System::name();
        let os_version = System::os_version();
        let kernel_version = System::kernel_version();
        let hostname = System::host_name();
        let distribution = System::distribution_id();
        let arch = System::cpu_arch();
        let container_runtime =
            in_container::get_container_runtime().map(|runtime| runtime.to_string());
        CrabResult::Host(HostCrabResult {
            os,
            os_version,
            kernel_version,
            hostname,
            distribution,
            arch,
            container_runtime,
        })
    }
    fn priority(&self) -> u64 {
        110
    }
}
