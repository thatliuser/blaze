mod crabs;
use crate::crabs::{
    creds::{CredentialsCrab, DatabaseCredential},
    db::{mysql::MysqlCrab, postgres::PostgresCrab},
    host::HostCrab,
    netstat::NetstatCrab,
    web::{httpd::HttpdCrab, nginx::NginxCrab},
};

fn main() {
    env_logger::init();
    println!("Hello, world!");
}
