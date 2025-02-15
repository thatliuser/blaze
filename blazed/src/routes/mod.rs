use crate::{
    AppState,
    models::{Host, Network},
};
use anyhow::Context;
use axum::{
    Json,
    extract::{Query, State},
    http::{
        StatusCode, Uri,
        uri::{PathAndQuery, Scheme},
    },
};
use futures::future::TryFutureExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct CreateNetwork {
    network: Network,
    hosts: HashMap<String, Host>,
}

async fn do_create_network(pool: &sqlx::SqlitePool, network: CreateNetwork) -> anyhow::Result<()> {
    for (_, host) in network.hosts.iter() {
        host.insert(&network.network, pool).await?;
    }
    network.network.insert(pool).await?;
    Ok(())
}

pub async fn create_network(
    State(state): State<AppState>,
    Json(network): Json<CreateNetwork>,
) -> (StatusCode, String) {
    match do_create_network(&state.pool, network).await {
        Ok(()) => (StatusCode::OK, "".into()),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn do_get_networks(pool: &sqlx::SqlitePool) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&Network::all(pool).await?)?)
}

pub async fn get_networks(State(state): State<AppState>) -> (StatusCode, String) {
    match do_get_networks(&state.pool).await {
        Ok(json) => (StatusCode::OK, json),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct QuotientPoint {
    pub x: String,
    pub y: i32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct QuotientSeries {
    pub name: String,
    pub data: Vec<QuotientPoint>,
}

#[derive(Serialize, Deserialize)]
pub struct QuotientServiceStatus {
    pub series: Vec<QuotientSeries>,
}

async fn do_import_quotient(pool: &sqlx::SqlitePool, host: &str) -> anyhow::Result<()> {
    let slug = PathAndQuery::from_static("/api/graphs/services");
    let uri: Uri = host.parse()?;
    // If there's no URI scheme, try HTTP first, then HTTPS
    let resp = if uri.scheme().is_none() {
        println!("No URI scheme, trying http/https");
        let mut http = uri.clone().into_parts();
        http.scheme = Some(Scheme::HTTP);
        http.path_and_query = Some(slug.clone());
        let http = Uri::from_parts(http)?;
        println!("HTTP URI: {}", http);
        let mut https = uri.clone().into_parts();
        https.scheme = Some(Scheme::HTTPS);
        https.path_and_query = Some(slug);
        let https = Uri::from_parts(https)?;
        println!("HTTPS URI: {}", https);
        // Try HTTP first, then HTTPS
        reqwest::get(http.to_string())
            .or_else(|_| reqwest::get(https.to_string()))
            .await?
            .json::<QuotientServiceStatus>()
            .await?
    } else {
        let mut parts = uri.into_parts();
        parts.path_and_query = Some(slug);
        let uri = Uri::from_parts(parts)?;
        reqwest::get(uri.to_string())
            .await?
            .json::<QuotientServiceStatus>()
            .await?
    };
    let series = resp
        .series
        .iter()
        .next()
        .context("Quotient returned an empty array of teams")?;
    for service in series.data.iter() {
        sqlx::query!(
            "INSERT INTO Services (name, info, kind) VALUES (?, ?, ?)",
            service.x,
            "none!",
            "unknown"
        )
        .execute(pool)
        .await?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct ImportQuotient {
    pub uri: String,
}
pub async fn import_quotient(
    State(state): State<AppState>,
    query: Query<ImportQuotient>,
) -> (StatusCode, String) {
    println!("Running import quotient");
    match do_import_quotient(&state.pool, &query.uri).await {
        Ok(()) => (StatusCode::OK, "".into()),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

// TODO: There's more to this but IDRC about the stuff rn
struct DbService {
    pub name: String,
    pub info: String,
    pub kind: String,
    pub cidr: Option<String>,
    pub ip: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct Service {
    pub name: String,
}

async fn do_get_services(pool: &sqlx::SqlitePool) -> anyhow::Result<String> {
    let services: Vec<_> = sqlx::query_as!(DbService, "SELECT * FROM Services")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|service| Service {
            name: service.name.clone(),
        })
        .collect();
    Ok(serde_json::to_string(&services)?)
}

pub async fn get_services(State(state): State<AppState>) -> (StatusCode, String) {
    match do_get_services(&state.pool).await {
        Ok(json) => (StatusCode::OK, json),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}
