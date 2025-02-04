pub mod container;
pub mod creds;
pub mod db;
pub mod host;
pub mod netstat;
pub mod web;

pub trait Crab {
    type Result;

    fn run(&self) -> Self::Result;
}
