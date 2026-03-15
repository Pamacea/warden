use axum::{
    extract::{Path, Query},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // Build our application with some routes
    let app = Router::new()
        .route("/", get(index))
        .route("/user/:id", get(get_user))
        .route("/search", get(search))
        .route("/exec", get(execute_command))
        .route("/env", get(get_env_var));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> &'static str {
    "Welcome to Vulnerable App!"
}

// VULNERABILITY: No input validation, potential SQL injection
async fn get_user(Path(id): Path<String>) -> Json<User> {
    // TODO: Fix this - unsanitized user input
    let query = format!("SELECT * FROM users WHERE id = {}", id); // VULNERABLE!

    User {
        id: id.clone(),
        name: "John Doe".to_string(),
        email: "john@example.com".to_string(),
    }
    .into()
}

// VULNERABILITY: Command injection possible
async fn execute_command(Query(params): Query<HashMap<String, String>>) -> String {
    let cmd = params.get("cmd").unwrap_or(&"echo hello".to_string()).clone();

    // DANGEROUS: Direct command execution with user input
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .unwrap();

    String::from_utf8_lossy(&output.stdout).to_string()
}

// VULNERABILITY: Environment variable exposure
async fn get_env_var() -> Json<serde_json::Value> {
    // Exposing sensitive environment variables
    let mut env_data = serde_json::Map::new();

    for (key, value) in std::env::vars() {
        if key.contains("SECRET") || key.contains("PASSWORD") || key.contains("TOKEN") {
            env_data.insert(key, serde_json::json!(value));
        }
    }

    serde_json::to_value(env_data).unwrap().into()
}

// VULNERABILITY: Unsafe unwrap on user input
async fn search(Query(params): Query<HashMap<String, String>>) -> Json<Vec<String>> {
    let query = params.get("q").unwrap(); // Will panic if missing!

    let results = vec![
        format!("Result 1 for: {}", query),
        format!("Result 2 for: {}", query),
    ];

    results.into()
}

#[derive(Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
    email: String,
}
