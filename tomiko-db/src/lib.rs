#![allow(clippy::toplevel_ref_arg)]

use tomiko_core::models::{AuthCodeData, Client, RedirectRecord};
use tomiko_core::types::{AuthCode, ClientId, HashedClientSecret, RedirectUri, Scope};

use sqlx::sqlite::SqlitePool;
use std::time::SystemTime;

#[async_trait::async_trait]
pub trait Store {
    async fn check_client_uri(&self, client_id: &ClientId, uri: &RedirectUri) -> Result<(), ()>;
    async fn store_code(&self, data: AuthCodeData, expiry: SystemTime) -> Result<AuthCodeData, ()>;
    async fn get_client(&self, client_id: &ClientId) -> Result<Client, ()>;
    async fn put_client(
        &self,
        client_id: ClientId,
        secret: HashedClientSecret,
    ) -> Result<Client, ()>;
    async fn get_authcode_data(
        &self,
        client_id: &ClientId,
        code: &AuthCode,
    ) -> Result<AuthCodeData, ()>;
    async fn clean_up() -> Result<(), ()>;
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
    async fn store_code(&self, data: AuthCodeData, expiry: SystemTime) -> Result<AuthCodeData, ()> {
        use std::convert::TryInto;

        let scope = data.scope.as_ref().map(|s| s.as_joined());
        let invalid_after: i64 = expiry
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .unwrap();

        sqlx::query!(
            "INSERT INTO codes(client_id, code, state, uri, scope, invalid_after) VALUES(?, ?, ?, ?, ?, ?)",
            data.client_id.0,
            data.code.0,
            data.state,
            data.redirect_uri.0,
            scope,
	    invalid_after
        )
        .execute(&self.pool)
        .await
        .map_err(|_| ())?;

        Ok(data)
    }

    async fn get_client(&self, id: &ClientId) -> Result<Client, ()> {
        sqlx::query!("SELECT * from clients WHERE client_id = ?", id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| ())?
            .map(|r| Client {
                id: ClientId(r.client_id),
                secret: HashedClientSecret(r.secret_hash),
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

    async fn get_authcode_data(
        &self,
        client_id: &ClientId,
        code: &AuthCode,
    ) -> Result<AuthCodeData, ()> {
        let result = sqlx::query!(
            "SELECT * FROM codes WHERE client_id = ? AND code = ?",
            client_id.0,
            code.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ())?
        .map(|r| AuthCodeData {
            client_id: ClientId(r.client_id),
            code: AuthCode(r.code),
            state: r.state,
            redirect_uri: RedirectUri(r.uri),
            scope: r.scope.map(Scope::from_delimited_parts),
        });

        result.ok_or(())
    }

    async fn clean_up() -> Result<(), ()> {
    }
}
