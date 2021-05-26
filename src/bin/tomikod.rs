#[tokio::main]
async fn main() -> Result<(), ()> {
    tomiko::provider::main().await
}
