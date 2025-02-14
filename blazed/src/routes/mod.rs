use std::collections::HashMap;

use axum::{Json, extract::State, http::StatusCode};

use crate::{
    AppState,
    models::{Host, Network},
};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateNetwork {
    network: Network,
    hosts: HashMap<String, Host>,
}

pub async fn create_network(
    State(state): State<AppState>,
    Json(network): Json<CreateNetwork>,
) -> (StatusCode, String) {
    for (_, host) in network.hosts.iter() {
        host.insert(&network.network, &state.pool).await;
    }
    network.network.insert(&state.pool).await;
    (StatusCode::OK, "".into())
}

pub async fn get_networks(State(state): State<AppState>) -> (StatusCode, String) {
    (
        StatusCode::OK,
        serde_json::to_string(&Network::all(&state.pool).await.unwrap()).unwrap(),
    )
}
