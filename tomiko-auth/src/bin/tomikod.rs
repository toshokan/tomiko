use warp::Filter;

#[tokio::main]
async fn main() {
    let oauth = warp::path("oauth");
    
    let v1 = oauth
        .and(warp::path("v1"))
        .map(|| {
	    format!("Hello world!")
	});
    
    warp::serve(v1).run(([127, 0, 0, 1], 8001)).await;
}
