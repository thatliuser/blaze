pub mod container;
pub mod creds;
pub mod db;
pub mod host;
pub mod netstat;
pub mod web;

use core::cmp::{Ordering, PartialOrd};
use serde::Serialize;

#[derive(Serialize)]
pub enum CrabResult {
    Credentials(creds::CredentialsCrabResult),
    Database(db::DatabaseCrabResult),
    Host(host::HostCrabResult),
    Netstat(netstat::NetstatCrabResult),
    Web(web::WebCrabResult),
    Container(container::ContainerCrabResult),
}

pub trait Crab {
    fn run(&self) -> CrabResult;
    fn priority(&self) -> u64;
}

impl PartialEq for dyn Crab {
    fn eq(&self, other: &Self) -> bool {
        self.priority() == other.priority()
    }
}

impl PartialOrd for dyn Crab {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.priority().cmp(&other.priority()))
    }
}
