use clap::Parser;

#[tokio::main]
async fn main() {
    use tomiko::util::cli::*;

    dotenv::dotenv().ok();

    let opts = Options::parse();
    run_cli_action(opts);
    println!("OK!");
}
