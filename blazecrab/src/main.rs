mod crabs;

use crabs::{
    creds::{CredentialsCrab, DatabaseCredential},
    db::{mysql::MysqlCrab, postgres::PostgresCrab},
    host::HostCrab,
    netstat::NetstatCrab,
    web::{httpd::HttpdCrab, nginx::NginxCrab},
    {Crab, CrabResult},
};
use std::collections::BinaryHeap;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let crabs: Vec<Box<dyn Crab>> = vec![
        Box::new(HostCrab {}),
        Box::new(NetstatCrab {}),
        /*
        Box::new(CredentialsCrab {}),
        Box::new(MysqlCrab {}),
        Box::new(PostgresCrab {}),
        Box::new(HttpdCrab {}),
        Box::new(NginxCrab {}),
        */
    ];
    let mut results: Vec<CrabResult> = vec![];
    let mut queue = BinaryHeap::from(crabs);
    while let Some(crab) = queue.pop() {
        let result = crab.run();
        results.push(result);
    }
    let json = serde_json::to_string_pretty(&results)?;
    println!("{}", json);
    Ok(())
}
