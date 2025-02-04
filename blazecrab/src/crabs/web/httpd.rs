use crate::crabs::{Crab, CrabResult};

pub struct HttpdCrab {}

impl Crab for HttpdCrab {
    fn run(&self) -> CrabResult {
        todo!()
    }
    fn priority(&self) -> u64 {
        90
    }
}
