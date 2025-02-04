pub mod mysql;
pub mod postgres;

pub struct DatabaseCrabResult {
    pub users: (),
    pub databases: (),
}
