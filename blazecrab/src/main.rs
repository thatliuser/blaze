mod crabs;
use crabs::Crab;

use crate::crabs::{
    creds::{CredentialsCrab, DatabaseCredential},
    db::{mysql::MysqlCrab, postgres::PostgresCrab},
    host::HostCrab,
    netstat::NetstatCrab,
    web::{httpd::HttpdCrab, nginx::NginxCrab},
};
use std::collections::BinaryHeap;

fn main() {
    env_logger::init();
    let queue = BinaryHeap::<&dyn Crab>::new();
    queue.push(&HostCrab);
    println!("Hello, world!");
}
