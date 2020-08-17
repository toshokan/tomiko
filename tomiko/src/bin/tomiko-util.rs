use clap::Clap;
use sqlx::sqlite::SqlitePool;

use tomiko_core::types::ClientSecret;
use tomiko_util::hash::HashingService;

#[derive(Clap)]
#[clap(version = env!("CARGO_PKG_VERSION"), author = env!("CARGO_PKG_AUTHORS"))]
struct Options {
    #[clap(env = "DATABASE_URL")]
    database_url: String,
    #[clap(env = "HASH_SECRET")]
    hash_secret: String,
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    CreateClient(CreateClient),
    DeleteClient(DeleteClient),
    AddClientUri(AddClientUri),
    DeleteClientUri(DeleteClientUri),
    AddClientScope(AddClientScope),
    DeleteClientScope(DeleteClientScope)
}

#[derive(Clap)]
struct CreateClient {
    #[clap(short, long)]
    id: String,
    #[clap(short, long)]
    secret: String,
}

#[derive(Clap)]
struct DeleteClient {
    #[clap(short, long)]
    id: String,
}

#[derive(Clap)]
struct AddClientUri {
    #[clap(short, long)]
    id: String,
    #[clap(short, long)]
    uri: String,
}

#[derive(Clap)]
struct DeleteClientUri {
    #[clap(short, long)]
    id: String,
    #[clap(short, long)]
    uri: String,
}

#[derive(Clap)]
struct AddClientScope {
    #[clap(short, long)]
    id: String,
    #[clap(short, long)]
    scope: String
}

#[derive(Clap)]
struct DeleteClientScope {
    #[clap(short, long)]
    id: String,
    #[clap(short, long)]
    scope: String
}

async fn get_database(uri: &str) -> SqlitePool {
    use sqlx::sqlite::SqlitePoolOptions;
    let pool = SqlitePoolOptions::new()
        .connect(uri)
        .await
        .expect("Failed to connect to database");
    pool
}

fn get_hasher(secret: &str) -> HashingService {
    HashingService::with_secret_key(secret.to_string())
}

async fn create_client(c: &CreateClient, opts: &Options) {
    let db = get_database(&opts.database_url).await;
    let hasher = get_hasher(&opts.hash_secret);

    let client_id = c.id.to_string();
    let password = hasher
        .hash(&ClientSecret(c.secret.to_string()))
        .expect("Failed to hash password")
        .0;

    sqlx::query!(
        "INSERT INTO clients(client_id, secret_hash) VALUES(?, ?)",
        client_id,
        password
    )
    .execute(&db)
    .await
    .expect("Failed to add client");

    println!("OK!")
}

async fn delete_client(c: &DeleteClient, opts: &Options) {
    let db = get_database(&opts.database_url).await;

    sqlx::query!("DELETE FROM clients WHERE client_id = ?", c.id)
        .execute(&db)
        .await
        .expect("Failed to delete client");

    println!("OK!")
}

async fn add_client_uri(c: &AddClientUri, opts: &Options) {
    let db = get_database(&opts.database_url).await;

    sqlx::query!("INSERT INTO uris(client_id, uri) VALUES(?, ?)", c.id, c.uri)
        .execute(&db)
        .await
        .expect("Failed to add url");

    println!("OK!")
}

async fn delete_client_uri(c: &DeleteClientUri, opts: &Options) {
    let db = get_database(&opts.database_url).await;

    sqlx::query!(
        "DELETE FROM uris WHERE client_id = ? AND uri = ?",
        c.id,
        c.uri
    )
    .execute(&db)
    .await
    .expect("Failed to remove url");

    println!("OK!")
}

async fn add_client_scope(c: &AddClientScope, opts: &Options) {
    let db = get_database(&opts.database_url).await;

    let scopes = c.scope.split(" ");

    for scope in scopes {
	sqlx::query!("INSERT INTO client_scopes(client_id, scope) VALUES(?, ?)", c.id, scope)
            .execute(&db)
            .await
            .expect("Failed to add scope");	
    }

    println!("OK!")
}

async fn delete_client_scope(c: &DeleteClientScope, opts: &Options) {
    let db = get_database(&opts.database_url).await;

    let scopes = c.scope.split(" ");

    for scope in scopes {
	sqlx::query!("DELETE FROM client_scopes WHERE client_id = ? AND scope = ?", c.id, scope)
            .execute(&db)
            .await
            .expect("Failed to delete scope");	
    }

    println!("OK!")
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let opts = Options::parse();
    use SubCommand::*;

    match &opts.command {
        CreateClient(c) => create_client(c, &opts).await,
        DeleteClient(c) => delete_client(c, &opts).await,
        AddClientUri(c) => add_client_uri(c, &opts).await,
        DeleteClientUri(c) => delete_client_uri(c, &opts).await,
	AddClientScope(c) => add_client_scope(c, &opts).await,
        DeleteClientScope(c) => delete_client_scope(c, &opts).await,
    };
}
