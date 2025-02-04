use crate::crabs::{Crab, CrabResult};

pub struct NginxCrab {}

impl Crab for NginxCrab {
    fn run(&self) -> CrabResult {
        todo!()
    }
    fn priority(&self) -> u64 {
        90
    }
}
