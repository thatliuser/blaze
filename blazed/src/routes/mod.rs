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
    response::{IntoResponse, Response},
};
use futures::future::TryFutureExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

pub type AppResult<T> = axum::response::Result<T, AppError>;

pub type JsonResponse<T> = AppResult<Json<T>>;

#[derive(Serialize, Deserialize)]
pub struct CreateNetwork {
    network: Network,
    hosts: HashMap<String, Host>,
}

pub async fn create_network(
    State(state): State<AppState>,
    Json(network): Json<CreateNetwork>,
) -> AppResult<()> {
    for (_, host) in network.hosts.iter() {
        host.insert(&network.network, &state.pool).await?;
    }
    network.network.insert(&state.pool).await?;
    Ok(())
}

pub async fn get_networks(State(state): State<AppState>) -> JsonResponse<Vec<Network>> {
    Ok(Json(Network::all(&state.pool).await?))
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

#[derive(Serialize, Deserialize)]
pub struct ImportQuotient {
    pub uri: String,
}

pub async fn import_quotient(
    State(state): State<AppState>,
    Query(query): Query<ImportQuotient>,
) -> AppResult<()> {
    let slug = PathAndQuery::from_static("/api/graphs/services");
    let uri: Uri = query.uri.parse()?;
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
        .execute(&state.pool)
        .await?;
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct Service {
    pub name: String,
}

pub async fn get_services(State(state): State<AppState>) -> JsonResponse<Vec<Service>> {
    let services: Vec<_> = sqlx::query!("SELECT * FROM Services")
        .fetch_all(&state.pool)
        .await?
        .iter()
        .map(|service| Service {
            name: service.name.clone(),
        })
        .collect();
    Ok(Json(services))
}

#[derive(Serialize, Deserialize)]
pub struct Password {
    pub id: i32,
    pub password: String,
}

pub async fn upload_passwords(
    State(state): State<AppState>,
    file: String,
) -> JsonResponse<Vec<Password>> {
    let passwords: Vec<_> = csv::Reader::from_reader(file.as_bytes())
        .deserialize::<Password>()
        .collect::<Result<_, _>>()?;
    for password in passwords.iter() {
        sqlx::query!(
            "INSERT INTO Passwords (round, id, password, kind) VALUES (?, ?, ?, ?)",
            0,
            password.id,
            password.password,
            "misc"
        )
        .execute(&state.pool)
        .await?;
    }
    Ok(Json(passwords))
}
