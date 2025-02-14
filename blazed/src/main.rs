use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use routes::{create_network, get_networks};
use sqlx::{Connection, SqliteConnection, SqlitePool};

mod db;
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
        .route("/networks", post(create_network).get(get_networks))
        .with_state(AppState { pool });
    let list = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    println!("Listening");
    axum::serve(list, app).await.unwrap();
}
