use tomiko_core::types::{
    AuthCode,
    ClientId,
    RedirectUri
};

mod types;

use types::RedirectRecord;

use sqlx::sqlite::SqlitePool;

#[async_trait::async_trait]
pub trait Store {
    async fn check_client_uri(&self, client_id: &ClientId, uri: &RedirectUri) -> Result<(), ()>;
    async fn store_code(&self, client_id: &ClientId, code: AuthCode, state: &str) -> Result<AuthCode, ()>;
}

#[derive(Debug)]
pub struct DbStore {
    pool: SqlitePool
}

impl DbStore {
    pub async fn acquire(db_uri: &str) -> Result<Self, ()> {
	let pool = SqlitePool::builder()
	    .max_size(5)
	    .build(db_uri)
	    .await
	    .map_err(|_| ())?; // TODO
	
	Ok(Self {
	    pool
	})
    }
}

#[async_trait::async_trait]
impl Store for DbStore {
    async fn check_client_uri(&self, client_id: &ClientId, uri: &RedirectUri) -> Result<(), ()> {
	use sqlx::sqlite::SqliteQueryAs;
	
	let mut conn = self.pool.acquire().await.unwrap();
	let result = sqlx::query_as::<_, RedirectRecord>("SELECT * FROM uris WHERE client_id = ? AND uri = ?")
            .bind(&client_id)
            .bind(&uri)
	    .fetch_optional(&mut conn).await
	    .map_err(|_| ())?;

	if result.is_some() {
	    return Ok(())
	}
	Err(())
    }
    async fn store_code(&self, client_id: &ClientId, code: AuthCode, state: &str) -> Result<AuthCode, ()> {
	let mut conn = self.pool.acquire().await.unwrap();
	
	sqlx::query("INSERT INTO codes(client_id, code, state) VALUES(?, ?, ?)")
	    .bind(&client_id)
	    .bind(&code)
	    .bind(&state)
	    .execute(&mut conn).await
	    .map_err(|_| ())?;
	Ok(code)
    }
}

// async fn give_token(db: SqlitePool, client_id: &ClientId, code: &AuthCode) -> Result<String, ()> {
//     use sqlx::sqlite::SqliteQueryAs;
    
//     let mut tx = db.begin().await.unwrap();
//     let code: Option<(AuthCode,)> = sqlx::query_as("SELECT code FROM codes WHERE client_id = ? AND code = ?")
//         .bind(&client_id)
//         .bind(&code)
//         .fetch_optional(&mut tx).await.unwrap();
    
//     if let Some(c) = code {
// 	let r = sqlx::query("DELETE FROM codes WHERE client_id = ? AND code = ?")
// 	    .bind(&client_id)
// 	    .bind(&c.0)
// 	    .execute(&mut tx).await;
// 	if r.is_ok() {
// 	    tx.commit().await.unwrap();
// 	    return Ok("done!".to_string())
// 	}
//     }

//     Err(())
//     // Err(warp::reject::custom(ErrorResponse::default())) // TODO: Return the correct error
// }
