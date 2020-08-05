#![allow(clippy::toplevel_ref_arg)]

use tomiko_auth::HashedClientSecret;
use tomiko_core::types::{AuthCode, ClientId, RedirectUri};

mod types;

use types::{Client, RedirectRecord};

use sqlx::sqlite::SqlitePool;

#[async_trait::async_trait]
pub trait Store {
    async fn check_client_uri(&self, client_id: &ClientId, uri: &RedirectUri) -> Result<(), ()>;
    async fn store_code(
        &self,
        client_id: &ClientId,
        code: AuthCode,
        state: &Option<String>,
        uri: &RedirectUri,
    ) -> Result<AuthCode, ()>;
    async fn get_client(&self, client_id: &ClientId) -> Result<Client, ()>;
    async fn put_client(
        &self,
        client_id: ClientId,
        secret: HashedClientSecret,
    ) -> Result<Client, ()>;
    async fn get_authcode_uri(
        &self,
        client_id: &ClientId,
        code: &AuthCode,
    ) -> Result<RedirectUri, ()>;
}

#[derive(Debug)]
pub struct DbStore {
    pool: SqlitePool,
}

impl DbStore {
    pub async fn acquire(db_uri: &str) -> Result<Self, ()> {
        use sqlx::sqlite::SqlitePoolOptions;
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(db_uri)
            .await
            .map_err(|_| ())?;

        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl Store for DbStore {
    async fn check_client_uri(&self, client_id: &ClientId, uri: &RedirectUri) -> Result<(), ()> {
        let result: Option<RedirectRecord> = sqlx::query!(
            r#"SELECT * FROM uris WHERE client_id = ? AND uri = ?"#,
            client_id.0,
            uri.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ())?
        .map(|r| RedirectRecord {
            client_id: ClientId(r.client_id),
            uri: RedirectUri(r.uri),
        });

        if result.is_some() {
            return Ok(());
        }
        Err(())
    }
    async fn store_code(
        &self,
        client_id: &ClientId,
        code: AuthCode,
        state: &Option<String>,
        uri: &RedirectUri,
    ) -> Result<AuthCode, ()> {
        sqlx::query!(
            "INSERT INTO codes(client_id, code, state, uri) VALUES(?, ?, ?, ?)",
            client_id.0,
            code.0,
            state,
            uri.0
        )
        .execute(&self.pool)
        .await
        .map_err(|_| ())?;
        Ok(code)
    }

    async fn get_client(&self, id: &ClientId) -> Result<Client, ()> {
        sqlx::query!("SELECT * from clients WHERE client_id = ?", id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| ())?
            .map(|r| Client {
                id: ClientId(r.client_id),
                secret: HashedClientSecret::from_raw(r.secret_hash),
            })
            .ok_or(())
    }

    async fn put_client(
        &self,
        client_id: ClientId,
        secret: HashedClientSecret,
    ) -> Result<Client, ()> {
        sqlx::query!(
            "INSERT INTO clients(client_id, secret_hash) VALUES(?, ?)",
            client_id.0,
            secret.0
        )
        .execute(&self.pool)
        .await
        .map_err(|_| ())?;

        self.get_client(&client_id).await
    }

    async fn get_authcode_uri(
        &self,
        client_id: &ClientId,
        code: &AuthCode,
    ) -> Result<RedirectUri, ()> {
        let result = sqlx::query!(
            "SELECT uri FROM codes WHERE client_id = ? AND code = ?",
            client_id.0,
            code.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ())?;

        result.map(|r| RedirectUri(r.uri)).ok_or(())
    }
}
