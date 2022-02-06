use std::fmt::Debug;

use crate::auth::{ChallengeData, Store};
use crate::core::models::{
    AuthCodeData, Client, Consent, PersistentSeed, PersistentSeedId, RefreshTokenData,
    RefreshTokenId,
};
use crate::core::types::{
    ChallengeId, ClientId, Expire, HashedAuthCode, HashedClientSecret, RedirectUri, Scope,
};
use crate::db::models::Code;
use crate::provider::error::Error;

use diesel::prelude::*;
use diesel::r2d2::{Builder as PoolBuilder, ConnectionManager, Pool, PooledConnection};

use super::models;
use super::schema;

diesel_migrations::embed_migrations!("migrations");

pub struct DbStore {
    pool: Pool<ConnectionManager<PgConnection>>,
}

impl DbStore {
    pub fn acquire(uri: &str) -> Result<Self, Error> {
        let pool = PoolBuilder::new()
            .max_size(10)
            .build(ConnectionManager::new(uri))
            .unwrap();
        Ok(Self { pool })
    }

    fn conn(&self) -> PooledConnection<ConnectionManager<PgConnection>> {
        self.pool.get().unwrap()
    }

    pub fn migrate(&self) {
        embedded_migrations::run_with_output(&self.conn(), &mut std::io::stderr()).unwrap();
        eprintln!("Ran migrations");
    }
}

impl Debug for DbStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbStore").finish()
    }
}

use tokio::task::block_in_place;

impl Store for DbStore {
    fn check_client_uri(&self, id: &ClientId, uri: &RedirectUri) -> Result<(), Error> {
        use schema::uris::dsl::uris;

        block_in_place(|| {
            uris.find((&id.0, &uri.0))
                .first::<models::Uri>(&self.conn())
        })?;

        Ok(())
    }

    fn store_code(&self, data: AuthCodeData) -> Result<AuthCodeData, Error> {
        use schema::codes::dsl::codes;

        let invalid_after: i64 = AuthCodeData::expiry().into();
        let req = serde_json::to_string(&data.req)?;

        let code = data.clone();

        block_in_place(|| {
            diesel::insert_into(codes)
                .values(Code {
                    client_id: code.client_id.0,
                    code: code.code.0,
                    req,
                    invalid_after,
                    subject: code.subject,
                })
                .execute(&self.conn())
        })?;

        Ok(data)
    }

    fn get_client(&self, id: &ClientId) -> Result<Option<Client>, Error> {
        use schema::clients::dsl::clients;

        let found = block_in_place(|| {
            clients
                .find(&id.0)
                .first::<models::Client>(&self.conn())
                .optional()
        })?;

        Ok(found.map(|c| Client {
            id: ClientId(c.client_id),
            name: c.name,
            secret: HashedClientSecret(c.secret_hash),
        }))
    }

    fn put_client(
        &self,
        id: ClientId,
        name: String,
        secret: HashedClientSecret,
    ) -> Result<Client, Error> {
        use schema::clients::dsl::clients;

        let model = models::Client {
            client_id: id.0,
            secret_hash: secret.0.clone(),
            name,
        };

        let result = block_in_place(|| {
            diesel::insert_into(clients)
                .values(model)
                .get_result::<models::Client>(&self.conn())
        })?;

        Ok(Client {
            id: ClientId(result.client_id),
            secret: HashedClientSecret(result.secret_hash),
            name: result.name,
        })
    }

    fn take_authcode_data(
        &self,
        client_id: &ClientId,
        code: &HashedAuthCode,
    ) -> Result<AuthCodeData, Error> {
        use schema::codes::dsl::{self, codes};

        let code = block_in_place(|| {
            diesel::delete(codes.find(&code.0).filter(dsl::client_id.eq(&client_id.0)))
                .get_result::<models::Code>(&self.conn())
        })
        .map_err(|_| Error::BadRequest)?;

        Ok(AuthCodeData {
            code: HashedAuthCode(code.code),
            client_id: ClientId(code.client_id),
            req: serde_json::from_str(&code.req)?,
            subject: code.subject,
        })
    }

    fn clean_up(&self) -> Result<(), Error> {
        use std::convert::TryInto;
        use std::time::SystemTime;

        use schema::challenges::dsl::{self as challenges_dsl, challenges};
        use schema::codes::dsl::{self as codes_dsl, codes};
        use schema::refresh_tokens::dsl::{self as tokens_dsl, refresh_tokens};

        let time: i64 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .unwrap();

        block_in_place(|| {
            diesel::delete(codes.filter(codes_dsl::invalid_after.lt(time))).execute(&self.conn())
        })?;

        block_in_place(|| {
            diesel::delete(refresh_tokens.filter(tokens_dsl::invalid_after.lt(time)))
                .execute(&self.conn())
        })?;

        block_in_place(|| {
            diesel::delete(challenges.filter(challenges_dsl::invalid_after.lt(time)))
                .execute(&self.conn())
        })?;

        Ok(())
    }

    fn trim_client_scopes(&self, client_id: &ClientId, scope: &Scope) -> Result<Scope, Error> {
        use schema::client_scopes::dsl::{self, client_scopes};

        let requested_scopes = scope.as_parts();

        let allowed_scopes = block_in_place(|| {
            client_scopes
                .filter(dsl::client_id.eq(&client_id.0))
                .filter(dsl::scope.eq_any(requested_scopes))
                .select(dsl::scope)
                .get_results::<String>(&self.conn())
        })?;

        Ok(Scope::from_parts(allowed_scopes))
    }

    fn store_challenge_data(&self, info: ChallengeData) -> Result<ChallengeId, Error> {
        use schema::challenges::dsl::challenges;

        let id = info.id.clone();
        let req = serde_json::to_string(&info.req)?;
        let scope = info.scope.as_joined();

        let invalid_after: i64 = ChallengeData::expiry().into();

        let challenge = models::Challenge {
            id: info.id.0.clone(),
            req,
            ok: info.ok,
            subject: None,
            scope,
            invalid_after,
        };

        block_in_place(|| {
            diesel::insert_into(challenges)
                .values(challenge)
                .execute(&self.conn())
        })?;

        Ok(id)
    }

    fn get_challenge_data(&self, id: &ChallengeId) -> Result<Option<ChallengeData>, Error> {
        use schema::challenges::dsl::challenges;

        let data = block_in_place(|| {
            challenges
                .find(&id.0)
                .get_result::<models::Challenge>(&self.conn())
                .optional()
        })?;

        Ok(match data {
            Some(c) => Some(ChallengeData {
                id: ChallengeId(c.id),
                req: serde_json::from_str(&c.req)?,
                ok: c.ok,
                subject: c.subject,
                scope: Scope::from_delimited_parts(&c.scope),
            }),
            _ => None,
        })
    }

    fn delete_challenge_data(&self, id: &ChallengeId) -> Result<(), Error> {
        use schema::challenges::dsl::challenges;

        block_in_place(|| diesel::delete(challenges.find(&id.0)).execute(&self.conn()))?;

        Ok(())
    }

    fn update_challenge_data(&self, info: ChallengeData) -> Result<ChallengeData, Error> {
        use schema::challenges::dsl::{self, challenges};

        let id = info.id.clone();
        let req = serde_json::to_string(&info.req)?;
        let scope = info.scope.as_joined();

        block_in_place(|| {
            diesel::update(challenges.find(&id.0))
                .set((
                    dsl::req.eq(&req),
                    dsl::ok.eq(info.ok),
                    dsl::subject.eq(&info.subject),
                    dsl::scope.eq(scope),
                ))
                .execute(&self.conn())
        })?;

        Ok(info)
    }
}

impl DbStore {
    pub fn store_persistent_seed(&self, seed: &PersistentSeed) -> Result<(), Error> {
        use schema::persistent_seeds::dsl::persistent_seeds;

        let subject = seed.subject.clone();
        let auth_data = serde_json::to_string(&seed.auth_data)?;
        let seed_id = seed.id.0.clone();
        let client_id = seed.client_id.0.clone();

        let model = models::PersistentSeed {
            persistent_seed_id: seed_id,
            subject,
            auth_data,
            client_id,
        };

        block_in_place(|| {
            diesel::insert_into(persistent_seeds)
                .values(model)
                .execute(&self.conn())
        })?;

        Ok(())
    }

    pub fn get_seed(&self, id: PersistentSeedId) -> Result<Option<PersistentSeed>, Error> {
        use schema::persistent_seeds::dsl::persistent_seeds;

        let result = block_in_place(|| {
            persistent_seeds
                .find(&id.0)
                .first::<models::PersistentSeed>(&self.conn())
                .optional()
        })?;

        Ok(match result {
            Some(s) => Some(PersistentSeed {
                id: PersistentSeedId(s.persistent_seed_id),
                client_id: ClientId(s.client_id),
                subject: s.subject,
                auth_data: serde_json::from_str(&s.auth_data)?,
            }),
            _ => None,
        })
    }

    pub fn invalidate_seed(&self, id: PersistentSeedId) -> Result<(), Error> {
        use schema::persistent_seeds::dsl::persistent_seeds;
        use schema::refresh_tokens::dsl::{self as tokens_dsl, refresh_tokens};

        block_in_place(|| {
            self.conn().transaction::<_, diesel::result::Error, _>(|| {
                diesel::delete(refresh_tokens.filter(tokens_dsl::persistent_seed_id.eq(&id.0)))
                    .execute(&self.conn())?;

                diesel::delete(persistent_seeds.find(&id.0)).execute(&self.conn())?;

                Ok(())
            })
        })?;

        Ok(())
    }

    pub fn put_refresh_token(&self, data: RefreshTokenData) -> Result<(), Error> {
        use schema::refresh_tokens::dsl::refresh_tokens;

        let expiry = RefreshTokenData::expiry().into();

        let model = models::RefreshToken {
            refresh_token_id: data.id.0,
            invalid_after: expiry,
            persistent_seed_id: data.seed.0,
        };

        block_in_place(|| {
            diesel::insert_into(refresh_tokens)
                .values(model)
                .execute(&self.conn())
        })?;

        Ok(())
    }

    pub fn invalidate_refresh_token(&self, id: &RefreshTokenId) -> Result<(), Error> {
        use schema::refresh_tokens::dsl::refresh_tokens;

        block_in_place(|| diesel::delete(refresh_tokens.find(&id.0)).execute(&self.conn()))?;

        Ok(())
    }

    pub fn find_refresh_token_seed(
        &self,
        id: &RefreshTokenId,
    ) -> Result<Option<PersistentSeed>, Error> {
        use schema::persistent_seeds::dsl::persistent_seeds;
        use schema::refresh_tokens::dsl::refresh_tokens;

        let result = block_in_place(|| {
            refresh_tokens
                .find(&id.0)
                .inner_join(persistent_seeds)
                .first::<(models::RefreshToken, models::PersistentSeed)>(&self.conn())
                .optional()
        })?;

        Ok(match result {
            Some((_, s)) => Some(PersistentSeed {
                id: PersistentSeedId(s.persistent_seed_id),
                client_id: ClientId(s.client_id),
                subject: s.subject,
                auth_data: serde_json::from_str(&s.auth_data)?,
            }),
            _ => None,
        })
    }

    pub fn get_all_consents(&self, subject: &str) -> Result<Vec<Consent>, Error> {
        use diesel::dsl::sql;
        use schema::consent_scopes::dsl::{self, consent_scopes};

        let mut consents = block_in_place(|| {
            consent_scopes
                .filter(dsl::subject.eq(subject))
                .select((
                    dsl::client_id,
                    dsl::subject,
                    sql("string_agg(scope, ' ') as scope"),
                ))
                .group_by((dsl::client_id, dsl::subject))
                .get_results::<models::ConsentScope>(&self.conn())
        })?;

        Ok(consents
            .drain(..)
            .map(|c| Consent {
                client_id: ClientId(c.client_id),
                subject: c.subject,
                scope: Scope::from_delimited_parts(&c.scope),
            })
            .collect())
    }

    pub fn get_consent(&self, client_id: &ClientId, subject: &str) -> Result<Consent, Error> {
        use schema::consent_scopes::dsl::{self, consent_scopes};

        let scope_parts = block_in_place(|| {
            consent_scopes
                .filter(dsl::subject.eq(subject))
                .filter(dsl::client_id.eq(&client_id.0))
                .select(dsl::scope)
                .get_results::<String>(&self.conn())
        })?;

        Ok(Consent {
            client_id: client_id.clone(),
            subject: subject.to_string(),
            scope: Scope::from_parts(scope_parts),
        })
    }

    pub fn put_consent(&self, consent: Consent) -> Result<(), Error> {
        use schema::consent_scopes::dsl::consent_scopes;

        let parts = consent.scope.as_parts();

        block_in_place(|| {
            self.conn().transaction::<_, diesel::result::Error, _>(|| {
                for part in parts {
                    let model = models::ConsentScope {
                        client_id: consent.client_id.0.clone(),
                        subject: consent.subject.clone(),
                        scope: part,
                    };
                    diesel::insert_into(consent_scopes)
                        .values(model)
                        .on_conflict_do_nothing()
                        .execute(&self.conn())?;
                }
                Ok(())
            })
        })?;

        Ok(())
    }

    pub fn delete_consent(&self, client_id: &ClientId, subject: &str) -> Result<(), Error> {
        use schema::consent_scopes::dsl::{self, consent_scopes};

        block_in_place(|| {
            diesel::delete(
                consent_scopes
                    .filter(dsl::client_id.eq(&client_id.0))
                    .filter(dsl::subject.eq(subject)),
            )
            .execute(&self.conn())
        })?;

        Ok(())
    }
}
