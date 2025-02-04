pub mod mysql;
pub mod postgres;
use serde::Serialize;

#[derive(Serialize)]
pub struct DatabaseCrabResult {
    pub users: (),
    pub databases: (),
}
