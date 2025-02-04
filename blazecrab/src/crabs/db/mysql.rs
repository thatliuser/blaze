use crate::crabs::{Crab, CrabResult};

pub struct MysqlCrab {}

impl Crab for MysqlCrab {
    fn run(&self) -> CrabResult {
        todo!()
    }
    fn priority(&self) -> u64 {
        80
    }
}
