#![allow(clippy::toplevel_ref_arg)]

use crate::auth::{ChallengeData, Store};
use crate::core::models::{AuthCodeData, Client};
use crate::core::types::{AuthCode, ChallengeId, ClientId, HashedClientSecret, RedirectUri, Scope};

use sqlx::sqlite::SqlitePool;
use std::time::SystemTime;

#[derive(Debug)]
pub struct DbStore {
    pool: SqlitePool,
}

impl DbStore {
    pub async fn acquire(db_uri: &str) -> Result<Self, ()> {
        let pool = SqlitePool::connect(db_uri)
            .await
            .map_err(|e| {
		dbg!(e);
		()
	    })?;

        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl Store for DbStore {
    async fn check_client_uri(&self, client_id: &ClientId, uri: &RedirectUri) -> Result<(), ()> {
        let result = sqlx::query!(
            r#"SELECT * FROM uris WHERE client_id = ? AND uri = ?"#,
            client_id.0,
            uri.0
        )
        .fetch_optional(&self.pool)
        .await
            .map_err(|_| ())
            .map(|_| ());
	result

    }
    async fn store_code(&self, data: AuthCodeData, expiry: SystemTime) -> Result<AuthCodeData, ()> {
        use std::convert::TryInto;

        let invalid_after: i64 = expiry
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .unwrap();
	let req = serde_json::to_string(&data.req).expect("bad db serialize");

        sqlx::query!(
            "INSERT INTO codes(client_id, code, req, invalid_after, subject) VALUES(?, ?, ?, ?, ?)",
            data.client_id.0,
            data.code.0,
	    req,
	    invalid_after,
	    data.subject
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
            code: AuthCode(r.code),
	    client_id: ClientId(r.client_id),
	    req: serde_json::from_str(&r.req).expect("Bad db deserialize"),
	    subject: r.subject
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

    async fn store_challenge_data(&self, info: ChallengeData) -> Result<ChallengeId, ()> {
        let id = info.id.clone();
	let req = serde_json::to_string(&info.req).expect("Bad db serialize");

        sqlx::query!(
            "INSERT INTO challenges(id, req, ok) VALUES (?,?,?)",
            info.id.0,
	    req,
	    info.ok
        )
        .execute(&self.pool)
        .await
        .map_err(|_| ())?;

        Ok(id)
    }

    async fn get_challenge_data(
        &self,
        id: &ChallengeId,
    ) -> Result<Option<crate::auth::ChallengeData>, ()> {
        let result = sqlx::query!("SELECT * FROM challenges WHERE id = ?", id.0)
            .fetch_optional(&self.pool)
            .await
            .map(|r| {
                r.map(|r| ChallengeData {
                    id: ChallengeId(r.id),
                    req: serde_json::from_str(&r.req).expect("Bad db deserialize"),
		    ok: r.ok,
		    subject: r.subject
                })
            })
            .map_err(|_| ())?;

        Ok(result)
    }

    async fn update_challenge_data(&self, info: ChallengeData) -> Result<ChallengeData, ()> {
	let id = &info.id;
	let req = serde_json::to_string(&info.req).expect("Bad db serialize");
	
	let result = sqlx::query!(
	    "UPDATE challenges SET req = ?, ok = ?, subject = ? WHERE id = ?",
	    req,
	    info.ok,
	    info.subject,
	    id.0,
	)
	.execute(&self.pool)
	.await
	.map(|_| {
		info
	})
	.map_err(|_| ())?;

	Ok(result)
    }
}
