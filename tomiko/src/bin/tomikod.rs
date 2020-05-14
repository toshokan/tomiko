// async fn handle_reject(err: warp::Rejection) -> Result<impl warp::Reply, warp::Rejection> {
//     if let Some(e @ ErrorResponse { .. }) = err.find() {
// 	Ok(e.clone())
//     } else {
// 	Err(err)
//     }
// }

// fn with_db(pool: SqlitePool) -> impl Filter<Extract = (SqlitePool,), Error = Infallible> + Clone {
//     warp::any().map(move || pool.clone())
// }

// #[tokio::main]
// async fn main() {
//     dotenv::dotenv().ok();

//     let db_url = std::env::var("DATABASE_URL").expect("set DATABASE_URL");
//     let pool = SqlitePool::builder()
//         .max_size(1)
//         .build(&db_url).await.unwrap();
    
//     let oauth = warp::path("oauth");

//     let auth = warp::path("auth")
//         .and(with_db(pool.clone()))
// 	.and(warp::filters::query::query())
//         .and_then(authorize);

//     let token = warp::path("token")
//         .and(with_db(pool.clone()))
//         .and(warp::filters::method::post())
//         .and(warp::filters::body::form())
//         .and_then(give_token);

//     let routes = auth
// 	.or(token);
    
//     let v1 = oauth
//         .and(warp::path("v1"))
// 	.and(routes)
//         .recover(handle_reject);
    
//     warp::serve(v1).run(([127, 0, 0, 1], 8001)).await;
// }

// #[tokio::main]
// async fn main() {
    
// }

fn main() {
    
}
