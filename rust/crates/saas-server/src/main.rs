use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, time::Duration};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use service_api::{AgentService, AgentServiceConfig, AgentTurnRequest};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    agent: Arc<AgentService>,
    jwt_secret: Arc<String>,
    rate_limiter: Arc<Mutex<HashMap<String, Vec<i64>>>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    token: String,
    user_id: String,
}

#[derive(Debug, Deserialize)]
struct CreateSessionRequest {
    model: Option<String>,
    title: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionSummary {
    id: String,
    model: String,
    title: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct SendMessageRequest {
    model: Option<String>,
    prompt: String,
}

#[derive(Debug, Serialize)]
struct SendMessageResponse {
    session_id: String,
    assistant_text: String,
    usage_input_tokens: u32,
    usage_output_tokens: u32,
    usage_total_tokens: u32,
}

#[derive(Debug, Serialize)]
struct MessageRecord {
    role: String,
    content: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct SessionDetail {
    session: SessionSummary,
    messages: Vec<MessageRecord>,
}

#[derive(Debug, Serialize)]
struct UsageResponse {
    session_count: u32,
    message_count: u32,
    input_tokens: u32,
    output_tokens: u32,
    total_tokens: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Connection::open("saas.sqlite3")?;
    init_db(&db)?;

    let agent = AgentService::new(AgentServiceConfig::default());
    let state = AppState {
        db: Arc::new(Mutex::new(db)),
        agent: Arc::new(agent),
        jwt_secret: Arc::new(
            std::env::var("SAAS_JWT_SECRET").unwrap_or_else(|_| "dev-secret-change-me".to_string()),
        ),
        rate_limiter: Arc::new(Mutex::new(HashMap::new())),
    };

    let cors = if let Ok(origin) = std::env::var("SAAS_ALLOWED_ORIGIN") {
        if let Ok(value) = origin.parse() {
            CorsLayer::new()
                .allow_origin(value)
                .allow_headers(Any)
                .allow_methods(Any)
        } else {
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods(Any)
        }
    } else {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_headers(Any)
            .allow_methods(Any)
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/auth/signup", post(signup))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/sessions", post(create_session).get(list_sessions))
        .route("/api/v1/sessions/:id", get(get_session))
        .route(
            "/api/v1/sessions/:id/messages",
            post(send_message).get(list_session_messages),
        )
        .route("/api/v1/usage", get(get_usage))
        .with_state(state)
        .layer(cors);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("saas-server listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn signup(
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    validate_email_and_password(&req.email, &req.password)?;
    let user_id = Uuid::new_v4().to_string();
    let password_hash = hash_password(&req.password).map_err(internal_error)?;
    let now = Utc::now().to_rfc3339();
    {
        let db = state.db.lock().map_err(|_| internal_error("db lock poisoned"))?;
        db.execute(
            "INSERT INTO users (id, email, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![user_id, req.email, password_hash, now],
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("signup failed: {e}")))?;
    }

    let token = create_jwt(&user_id, &state.jwt_secret).map_err(internal_error)?;
    Ok(Json(AuthResponse { token, user_id }))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    validate_email_and_password(&req.email, &req.password)?;
    let (user_id, stored_hash) = {
        let db = state.db.lock().map_err(|_| internal_error("db lock poisoned"))?;
        db.query_row(
            "SELECT id, password_hash FROM users WHERE email = ?1",
            params![req.email],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(internal_error)?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid credentials".to_string()))?
    };

    let is_valid = verify_password(&req.password, &stored_hash).map_err(internal_error)?;
    if !is_valid {
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials".to_string()));
    }

    let token = create_jwt(&user_id, &state.jwt_secret).map_err(internal_error)?;
    Ok(Json(AuthResponse { token, user_id }))
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<SessionSummary>, (StatusCode, String)> {
    let user_id = auth_user_id(&headers, &state)?;
    enforce_rate_limit(&state, &user_id)?;
    let session_id = Uuid::new_v4().to_string();
    let model = req.model.unwrap_or_else(|| "claude-opus-5-0".to_string());
    let title = req.title.unwrap_or_else(|| "New session".to_string());
    let now = Utc::now().to_rfc3339();

    {
        let db = state.db.lock().map_err(|_| internal_error("db lock poisoned"))?;
        db.execute(
            "INSERT INTO sessions (id, user_id, model, title, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![session_id, user_id, model, title, now, now],
        )
        .map_err(internal_error)?;
    }

    Ok(Json(SessionSummary {
        id: session_id,
        model,
        title,
        created_at: now.clone(),
        updated_at: now,
    }))
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionSummary>>, (StatusCode, String)> {
    let user_id = auth_user_id(&headers, &state)?;
    let db = state.db.lock().map_err(|_| internal_error("db lock poisoned"))?;
    let mut stmt = db
        .prepare(
            "SELECT id, model, title, created_at, updated_at
             FROM sessions WHERE user_id = ?1 ORDER BY updated_at DESC",
        )
        .map_err(internal_error)?;
    let rows = stmt
        .query_map(params![user_id], |row| {
            Ok(SessionSummary {
                id: row.get(0)?,
                model: row.get(1)?,
                title: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })
        .map_err(internal_error)?;
    let mut sessions = Vec::new();
    for row in rows {
        sessions.push(row.map_err(internal_error)?);
    }
    Ok(Json(sessions))
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SessionDetail>, (StatusCode, String)> {
    let user_id = auth_user_id(&headers, &state)?;
    let db = state.db.lock().map_err(|_| internal_error("db lock poisoned"))?;
    let session = db
        .query_row(
            "SELECT id, model, title, created_at, updated_at FROM sessions WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
            |row| {
                Ok(SessionSummary {
                    id: row.get(0)?,
                    model: row.get(1)?,
                    title: row.get(2)?,
                    created_at: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(internal_error)?;
    match session {
        Some(session) => {
            let mut stmt = db
                .prepare(
                    "SELECT role, content, created_at
                     FROM messages
                     WHERE session_id = ?1
                     ORDER BY created_at ASC",
                )
                .map_err(internal_error)?;
            let rows = stmt
                .query_map(params![session.id], |row| {
                    Ok(MessageRecord {
                        role: row.get(0)?,
                        content: row.get(1)?,
                        created_at: row.get(2)?,
                    })
                })
                .map_err(internal_error)?;
            let mut messages = Vec::new();
            for row in rows {
                messages.push(row.map_err(internal_error)?);
            }
            Ok(Json(SessionDetail { session, messages }))
        }
        None => Err((StatusCode::NOT_FOUND, "session not found".to_string())),
    }
}

async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, (StatusCode, String)> {
    let user_id = auth_user_id(&headers, &state)?;
    enforce_rate_limit(&state, &user_id)?;
    validate_prompt(&req.prompt)?;
    let model = {
        let db = state.db.lock().map_err(|_| internal_error("db lock poisoned"))?;
        db.query_row(
            "SELECT model FROM sessions WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(internal_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "session not found".to_string()))?
    };

    let chosen_model = req.model.clone().unwrap_or(model);
    let turn = state
        .agent
        .run_turn(AgentTurnRequest {
            user_id,
            session_id: Some(id.clone()),
            model: chosen_model,
            prompt: req.prompt.clone(),
        })
        .map_err(internal_error)?;
    let assistant_text = turn
        .messages
        .iter()
        .map(|m| m.content.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let usage = turn.usage.unwrap_or(runtime::TokenUsage {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    });
    let now = Utc::now().to_rfc3339();
    {
        let db = state.db.lock().map_err(|_| internal_error("db lock poisoned"))?;
        db.execute(
            "INSERT INTO messages (id, session_id, role, content, usage_json, created_at)
             VALUES (?1, ?2, 'user', ?3, ?4, ?5)",
            params![
                Uuid::new_v4().to_string(),
                id,
                req.prompt.clone(),
                serde_json::json!({}),
                now
            ],
        )
        .map_err(internal_error)?;
        db.execute(
            "INSERT INTO messages (id, session_id, role, content, usage_json, created_at)
             VALUES (?1, ?2, 'assistant', ?3, ?4, ?5)",
            params![
                Uuid::new_v4().to_string(),
                id,
                assistant_text.clone(),
                serde_json::to_string(&usage).map_err(internal_error)?,
                now
            ],
        )
        .map_err(internal_error)?;
        db.execute(
            "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), id],
        )
        .map_err(internal_error)?;
    }

    Ok(Json(SendMessageResponse {
        session_id: turn.session_id,
        assistant_text,
        usage_input_tokens: usage.input_tokens,
        usage_output_tokens: usage.output_tokens,
        usage_total_tokens: usage.total_tokens(),
    }))
}

async fn get_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UsageResponse>, (StatusCode, String)> {
    let user_id = auth_user_id(&headers, &state)?;
    let db = state.db.lock().map_err(|_| internal_error("db lock poisoned"))?;
    let session_count = db
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ?1",
            params![&user_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(internal_error)? as u32;
    let message_count = db
        .query_row(
            "SELECT COUNT(*)
             FROM messages m
             JOIN sessions s ON s.id = m.session_id
             WHERE s.user_id = ?1",
            params![&user_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(internal_error)? as u32;

    let mut input_tokens = 0_u32;
    let mut output_tokens = 0_u32;
    let mut stmt = db
        .prepare(
            "SELECT m.usage_json
             FROM messages m
             JOIN sessions s ON s.id = m.session_id
             WHERE s.user_id = ?1 AND m.role = 'assistant'",
        )
        .map_err(internal_error)?;
    let rows = stmt
        .query_map(params![&user_id], |row| row.get::<_, String>(0))
        .map_err(internal_error)?;
    for row in rows {
        let raw = row.map_err(internal_error)?;
        if raw.is_empty() {
            continue;
        }
        if let Ok(usage) = serde_json::from_str::<runtime::TokenUsage>(&raw) {
            input_tokens += usage.input_tokens;
            output_tokens += usage.output_tokens;
        }
    }

    Ok(Json(UsageResponse {
        session_count,
        message_count,
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
    }))
}

async fn list_session_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<MessageRecord>>, (StatusCode, String)> {
    let user_id = auth_user_id(&headers, &state)?;
    let db = state.db.lock().map_err(|_| internal_error("db lock poisoned"))?;
    let session_exists = db
        .query_row(
            "SELECT id FROM sessions WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(internal_error)?;
    if session_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "session not found".to_string()));
    }
    let mut stmt = db
        .prepare(
            "SELECT role, content, created_at
             FROM messages
             WHERE session_id = ?1
             ORDER BY created_at ASC",
        )
        .map_err(internal_error)?;
    let rows = stmt
        .query_map(params![id], |row| {
            Ok(MessageRecord {
                role: row.get(0)?,
                content: row.get(1)?,
                created_at: row.get(2)?,
            })
        })
        .map_err(internal_error)?;
    let mut messages = Vec::new();
    for row in rows {
        messages.push(row.map_err(internal_error)?);
    }
    Ok(Json(messages))
}

fn auth_user_id(headers: &HeaderMap, state: &AppState) -> Result<String, (StatusCode, String)> {
    let token = bearer_token(headers)?;
    let decoded = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token".to_string()))?;
    Ok(decoded.claims.sub)
}

fn validate_email_and_password(email: &str, password: &str) -> Result<(), (StatusCode, String)> {
    if !email.contains('@') || email.len() > 160 {
        return Err((StatusCode::BAD_REQUEST, "invalid email".to_string()));
    }
    if password.len() < 8 || password.len() > 200 {
        return Err((
            StatusCode::BAD_REQUEST,
            "password must be between 8 and 200 chars".to_string(),
        ));
    }
    Ok(())
}

fn validate_prompt(prompt: &str) -> Result<(), (StatusCode, String)> {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "prompt is required".to_string()));
    }
    if trimmed.len() > 12_000 {
        return Err((StatusCode::BAD_REQUEST, "prompt too long".to_string()));
    }
    Ok(())
}

fn enforce_rate_limit(state: &AppState, user_id: &str) -> Result<(), (StatusCode, String)> {
    let window = Duration::from_secs(60);
    let max_requests = 60usize;
    let now = Utc::now().timestamp();
    let mut limiter = state
        .rate_limiter
        .lock()
        .map_err(|_| internal_error("rate limiter lock poisoned"))?;
    let entry = limiter.entry(user_id.to_string()).or_default();
    entry.retain(|ts| now - *ts <= window.as_secs() as i64);
    if entry.len() >= max_requests {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".to_string()));
    }
    entry.push(now);
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, (StatusCode, String)> {
    let header = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing authorization".to_string()))?
        .to_str()
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid authorization header".to_string()))?;
    header
        .strip_prefix("Bearer ")
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "expected Bearer token".to_string()))
}

fn create_jwt(user_id: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let exp = Utc::now().timestamp() + 86_400 * 7;
    let claims = Claims {
        sub: user_id.to_string(),
        exp: exp as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| e.to_string())
}

fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    let parsed = PasswordHash::new(hash).map_err(|e| e.to_string())?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

fn init_db(db: &Connection) -> Result<(), rusqlite::Error> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            model TEXT NOT NULL,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            usage_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES sessions(id)
        );",
    )
}

fn internal_error(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

