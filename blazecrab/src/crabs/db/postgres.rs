use crate::crabs::{Crab, CrabResult};

pub struct PostgresCrab {}

impl Crab for PostgresCrab {
    fn run(&self) -> CrabResult {
        todo!()
    }
    fn priority(&self) -> u64 {
        80
    }
}
