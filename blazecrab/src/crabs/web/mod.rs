pub mod httpd;
pub mod nginx;
use serde::Serialize;

#[derive(Serialize)]
pub struct WebCrabResult {}
