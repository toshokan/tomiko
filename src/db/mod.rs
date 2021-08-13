#![allow(clippy::toplevel_ref_arg)]

use crate::auth::{ChallengeData, Store};
use crate::core::models::{AuthCodeData, Client, Consent, PersistentSeed, PersistentSeedId, RefreshTokenId};
use crate::core::types::{ChallengeId, ClientId, Expire, HashedAuthCode, HashedClientSecret, RedirectUri, Scope};
use crate::provider::error::Error;

use sqlx::sqlite::SqlitePool;


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
        .fetch_one(&self.pool)
        .await
            .map_err(|_| ())
            .map(|_| ());
	result

    }
    async fn store_code(&self, data: AuthCodeData) -> Result<AuthCodeData, ()> {
        let invalid_after: i64 = AuthCodeData::expiry().into();
	
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

    async fn take_authcode_data(
        &self,
        client_id: &ClientId,
        code: &HashedAuthCode,
    ) -> Result<AuthCodeData, Error> {
	let mut tx = self.pool.begin().await?;
	
        let result = sqlx::query!(
            "SELECT * FROM codes WHERE client_id = ? AND code = ?",
            client_id.0,
            code.0
        )
        .fetch_optional(&mut tx)
        .await?
        .map(|r| AuthCodeData {
            code: HashedAuthCode(r.code),
	    client_id: ClientId(r.client_id),
	    req: serde_json::from_str(&r.req).expect("Bad db deserialize"),
	    subject: r.subject
        });

	sqlx::query!(
	    "DELETE FROM codes WHERE client_id = ? AND code = ?",
	    client_id.0,
	    code.0
	).execute(&mut tx)
	    .await?;

	tx.commit().await?;

	result.ok_or(Error::BadRequest)
    }

    async fn clean_up(&self) -> Result<(), ()> {
        use std::convert::TryInto;
	use std::time::SystemTime;

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
            .map(|_| ())?;

	sqlx::query!("DELETE FROM refresh_tokens WHERE invalid_after <= ?", time)
            .execute(&self.pool)
            .await
            .map_err(|_| ())
            .map(|_| ())?;

	sqlx::query!("DELETE FROM challenges WHERE invalid_after <= ?", time)
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
	let scope = info.scope.as_joined();

	let invalid_after: i64 = ChallengeData::expiry().into();

        sqlx::query!(
            "INSERT INTO challenges(id, req, ok, scope, invalid_after) VALUES (?,?,?,?,?)",
            info.id.0,
	    req,
	    info.ok,
	    scope,
	    invalid_after
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
		    subject: r.subject,
		    scope: Scope::from_delimited_parts(&r.scope)
                })
            })
            .map_err(|_| ())?;

        Ok(result)
    }

    async fn delete_challenge_data(
        &self,
        id: &ChallengeId,
    ) -> Result<(), ()> {
        sqlx::query!("DELETE FROM challenges WHERE id = ?", id.0)
            .execute(&self.pool)
            .await
            .map_err(|_| ())?;
	Ok(())
    }

    async fn update_challenge_data(&self, info: ChallengeData) -> Result<ChallengeData, ()> {
	let id = &info.id;
	let req = serde_json::to_string(&info.req).expect("Bad db serialize");
	let scope = info.scope.as_joined();
	
	let result = sqlx::query!(
	    "UPDATE challenges SET req = ?, ok = ?, subject = ?, scope = ? WHERE id = ?",
	    req,
	    info.ok,
	    info.subject,
	    scope,
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

impl DbStore {
    pub async fn store_persistent_seed(&self, seed: &PersistentSeed) -> Result<(), ()> {
	let subject = seed.auth_data.subject.clone();
	let auth_data = serde_json::to_string(&seed.auth_data).expect("Bad db serialize");
	let seed_id = &seed.id;
	let client_id = &seed.client_id;
	
	let _result = sqlx::query!(
	    "INSERT INTO persistent_seeds(persistent_seed_id, subject, auth_data, client_id) VALUES(?, ?, ?, ?)",
	    seed_id.0,
	    subject,
	    auth_data,
	    client_id.0
	)
	    .execute(&self.pool)
	    .await
	    .map_err(|_| ())?;

	Ok(())
    }

    pub async fn get_seed(&self, id: PersistentSeedId) -> Result<Option<PersistentSeed>, ()> {
	sqlx::query!(
	    "SELECT * FROM persistent_seeds WHERE persistent_seed_id = ?",
	    id.0
	).fetch_optional(&self.pool)
	    .await
	    .map(|r| {
		r.map(|r| {
		    PersistentSeed {
			id: PersistentSeedId(r.persistent_seed_id),
			client_id: ClientId(r.client_id),
			auth_data: serde_json::from_str(&r.auth_data).expect("Bad db deserialize"),
		    }
		})
	    }).map_err(|_| ())
    }

    pub async fn invalidate_seed(&self, id: PersistentSeedId) -> Option<()> {
	let mut tx = self.pool.begin().await.ok()?;
	sqlx::query!(
	    "DELETE FROM persistent_seeds WHERE persistent_seed_id = ?",
	    id.0
	).execute(&mut tx).await.ok()?;
	sqlx::query!(
	    "DELETE FROM refresh_tokens WHERE persistent_seed_id = ?",
	    id.0
	).execute(&mut tx).await.ok()?;
	tx.commit().await.ok()?;
	Some(())
    }

    pub async fn invalidate_refresh_token(&self, id: RefreshTokenId) -> Option<()> {
	sqlx::query!(
	    "DELETE FROM refresh_tokens WHERE refresh_token_id = ?",
	    id.0
	)
	    .execute(&self.pool)
	    .await
	    .ok()?;
	
	Some(())
    }

    pub async fn validate_refresh_token(&self, id: RefreshTokenId) -> Option<()> {
	sqlx::query!(
	    "SElECT * FROM refresh_tokens WHERE refresh_token_id = ?",
	    id.0
	).fetch_optional(&self.pool)
	    .await
	    .map(|_| ())
	    .ok()
    }

    pub async fn get_all_consents(&self, subject: &str) -> Result<Vec<Consent>, ()> {
	sqlx::query!(
	    r#"SELECT client_id, group_concat(scope, ' ') AS "scope!: String" FROM consent_scopes WHERE subject = ?"#,
	    subject
	).fetch_all(&self.pool)
	    .await
	    .map(|mut r| {
		r.drain(..)
		    .filter(|r| r.client_id != "")
		    .map(|r| {
		    Consent {
			client_id: ClientId(r.client_id),
			subject: subject.to_string(),
			scope: Scope::from_delimited_parts(&r.scope)
		    }
		}).collect()
	    }).map_err(|_| ())
    }

    pub async fn get_consent(&self, client_id: &ClientId, subject: &str) -> Result<Consent, ()> {
	let scope = sqlx::query!(
	    "SELECT scope FROM consent_scopes WHERE client_id = ? AND subject = ?",
	    client_id.0,
	    subject
	).fetch_all(&self.pool)
	    .await
	    .map(|mut r| {
		let parts = r.drain(..).map(|r| r.scope).collect();
		Scope::from_parts(parts)
	    }).map_err(|_| ())?;
	Ok(Consent {
	    client_id: client_id.clone(),
	    subject: subject.to_string(),
	    scope
	})
    }

    pub async fn put_consent(&self, consent: Consent) -> Result<(), ()> {
	let mut tx = self.pool.begin().await.map_err(|_| ())?;
	let parts = consent.scope.as_parts();
	for part in parts {
	    sqlx::query!(
		"INSERT OR IGNORE INTO consent_scopes(client_id, subject, scope) VALUES(?, ?, ?)",
		consent.client_id.0,
		consent.subject,
		part
	    ).execute(&mut tx)
		.await
		.map_err(|_| ())?;
	}
	tx.commit().await.map_err(|_| ())
    }

    pub async fn delete_consent(&self, client_id: &ClientId, subject: &str) -> Result<(), ()> {
	sqlx::query!(
	    "DELETE FROM consent_scopes WHERE client_id = ? AND subject = ?",
	    client_id.0,
	    subject
	).execute(&self.pool)
	    .await
	    .map(|_| ())
	    .map_err(|_| ())
    }
}
