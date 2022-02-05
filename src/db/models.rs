use super::schema::*;

#[derive(Debug)]
#[derive(Queryable, Insertable)]
pub struct Uri {
    pub client_id: String,
    pub uri: String
}

#[derive(Debug)]
#[derive(Queryable, Insertable)]
pub struct Code {
    pub client_id: String,
    pub code: String,
    pub req: String,
    pub invalid_after: i64,
    pub subject: String
}

#[derive(Debug)]
#[derive(Queryable, Insertable)]
pub struct Client {
    pub client_id: String,
    pub secret_hash: String,
    pub name: String
}

#[derive(Debug)]
#[derive(Queryable, Insertable)]
pub struct ClientScope {
    pub client_id: String,
    pub scope: String
}

#[derive(Debug)]
#[derive(Queryable, Insertable)]
pub struct Challenge {
    pub id: String,
    pub req: String,
    pub ok: bool,
    pub subject: Option<String>,
    pub scope: String,
    pub invalid_after: i64
}

#[derive(Debug)]
#[derive(Queryable, Insertable)]
pub struct PersistentSeed {
    pub persistent_seed_id: String,
    pub subject: String,
    pub auth_data: String,
    pub client_id: String
}

#[derive(Debug)]
#[derive(Queryable, Insertable)]
pub struct RefreshToken {
    pub refresh_token_id: String,
    pub invalid_after: i64,
    pub persistent_seed_id: String
}

#[derive(Debug)]
#[derive(Queryable, Insertable)]
pub struct ConsentScope {
    pub client_id: String,
    pub subject: String,
    pub scope: String,
}
