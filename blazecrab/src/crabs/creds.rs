use crate::crabs::Crab;
use serde::Serialize;

pub struct CredentialsCrab {}

impl Crab for CredentialsCrab {
    type Result = CredentialsCrabResult;
}

#[derive(Serialize)]
pub struct CredentialsCrabResult {
    pub findings: (),
}

#[derive(Clone, Debug)]
pub struct DatabaseCredential {}
