use tomiko_auth::AuthenticationCodeFlow;

struct Server<T> {
    driver: T
}

impl<T: AuthenticationCodeFlow> Server<T> {
    async fn serve() -> Option<()> {
	Some(())
    }
}
