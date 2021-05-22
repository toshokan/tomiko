#![allow(clippy::toplevel_ref_arg)]

use crate::auth::{ChallengeInfo, Store};
use crate::core::models::{AuthCodeData, Client, RedirectRecord};
use crate::core::types::{AuthCode, ChallengeId, ClientId, HashedClientSecret, RedirectUri, Scope};

use sqlx::sqlite::SqlitePool;
use std::time::SystemTime;

#[derive(Debug)]
pub struct DbStore {
    pool: SqlitePool,
}

impl DbStore {
    pub async fn acquire(db_uri: &str) -> Result<Self, ()> {
        let pool = SqlitePool::builder()
            .max_size(5)
            .build(db_uri)
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

    async fn get_client(&self, id: &ClientId) -> Result<Option<Client>, ()> {
        let result = sqlx::query!("SELECT * from clients WHERE client_id = ?", id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| ())?
            .map(|r| Client {
                id: ClientId(r.client_id),
                secret: HashedClientSecret(r.secret_hash),
            });
        Ok(result)
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

        let client = self
            .get_client(&client_id)
            .await?
            .expect("Client disappeared");
        Ok(client)
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
            scope: r.scope.map(|s| Scope::from_delimited_parts(&s)),
        });

        result.ok_or(())
    }

    async fn clean_up(&self) -> Result<(), ()> {
        use std::convert::TryInto;

        let time: i64 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .unwrap();

        sqlx::query!("DELETE FROM codes WHERE invalid_after <= ?", time)
            .execute(&self.pool)
            .await
            .map_err(|_| ())
            .map(|_| ())
    }

    async fn trim_client_scopes(&self, client_id: &ClientId, scope: &Scope) -> Result<Scope, ()> {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        let mut results = sqlx::query!(
            "SELECT scope FROM client_scopes WHERE client_id = ?",
            client_id.0
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ())?;

        let results = results.drain(..).map(move |r| r.scope);

        let allowed_scopes: HashSet<String> = HashSet::from_iter(results);

        let parts = scope
            .as_parts()
            .drain(..)
            .filter(|p| allowed_scopes.contains(p))
            .collect();

        Ok(Scope::from_parts(parts))
    }

    async fn store_challenge_info(&self, info: ChallengeInfo) -> Result<ChallengeId, ()> {
        let id = info.id.clone();

        sqlx::query!(
            "INSERT INTO challenges(id, client_id, uri, scope, state) VALUES (?,?,?,?,?)",
            info.id.0,
            info.client_id.0,
            info.uri.0,
            info.scope.as_joined(),
            info.state
        )
        .execute(&self.pool)
        .await
        .map_err(|_| ())?;

        Ok(id)
    }

    async fn get_challenge_info(
        &self,
        id: ChallengeId,
    ) -> Result<Option<crate::auth::ChallengeInfo>, ()> {
        let result = sqlx::query!("SELECT * FROM challenges WHERE id = ?", id.0)
            .fetch_optional(&self.pool)
            .await
            .map(|r| {
                r.map(|r| ChallengeInfo {
                    id: ChallengeId(r.id),
                    client_id: ClientId(r.client_id),
                    uri: RedirectUri(r.uri),
                    scope: Scope::from_delimited_parts(&r.scope),
                    state: r.state,
                })
            })
            .map_err(|_| ())?;

        Ok(result)
    }
}
