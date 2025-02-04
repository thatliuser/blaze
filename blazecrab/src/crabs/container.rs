use crate::crabs::{Crab, CrabResult};
use serde::Serialize;

pub struct ContainerCrab {}

impl Crab for ContainerCrab {
    fn run(&self) -> CrabResult {
        todo!()
    }
    fn priority(&self) -> u64 {
        70
    }
}

#[derive(Serialize)]
pub struct ContainerCrabResult {}
