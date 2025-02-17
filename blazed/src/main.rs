use axum::{
    Router,
    routing::{get, post},
};
use routes::{create_network, get_networks, get_services, import_quotient, upload_passwords};
use sqlx::SqlitePool;

mod models;
mod routes;

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
}

#[tokio::main]
async fn main() {
    let pool = SqlitePool::connect("blaze.db?mode=rwc").await.unwrap();
    sqlx::migrate!().run(&pool).await.unwrap();
    let app = Router::new()
        .route("/api/networks", post(create_network).get(get_networks))
        .route("/api/services/quotient", get(import_quotient))
        .route("/api/services", get(get_services))
        .route("/api/passwords", post(upload_passwords))
        .with_state(AppState { pool });
    let list = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    println!("Listening");
    axum::serve(list, app).await.unwrap();
}
