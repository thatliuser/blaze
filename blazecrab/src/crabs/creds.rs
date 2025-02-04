use crate::crabs::{Crab, CrabResult};
use serde::Serialize;

pub struct CredentialsCrab {}

impl Crab for CredentialsCrab {
    fn run(&self) -> CrabResult {
        todo!()
    }
    fn priority(&self) -> u64 {
        85
    }
}

#[derive(Serialize)]
pub struct CredentialsCrabResult {
    pub findings: (),
}

#[derive(Clone, Debug)]
pub struct DatabaseCredential {}
