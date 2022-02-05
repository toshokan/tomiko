use crate::core::types::ClientSecret;
use crate::core::types::Scope;
use crate::util::hash::HashingService;

use clap::Parser;
use diesel::PgConnection;

use crate::db::schema;
use crate::db::models;

use diesel::prelude::*;

#[derive(Parser)]
#[clap(
    name = "tomiko-util",
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS")
)]
pub struct Options {
    #[clap(env = "DATABASE_URL")]
    database_url: String,
    #[clap(env = "HASH_SECRET")]
    hash_secret: String,
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    CreateClient(CreateClient),
    DeleteClient(DeleteClient),
    AddClientUri(AddClientUri),
    DeleteClientUri(DeleteClientUri),
    AddClientScope(AddClientScope),
    DeleteClientScope(DeleteClientScope),
}

#[derive(Parser)]
struct CreateClient {
    #[clap(short, long)]
    id: String,
    #[clap(short, long)]
    name: String,
    #[clap(short, long)]
    secret: String,
}

#[derive(Parser)]
struct DeleteClient {
    #[clap(short, long)]
    id: String,
}

#[derive(Parser)]
struct AddClientUri {
    #[clap(short, long)]
    id: String,
    #[clap(short, long)]
    uri: String,
}

#[derive(Parser)]
struct DeleteClientUri {
    #[clap(short, long)]
    id: String,
    #[clap(short, long)]
    uri: String,
}

#[derive(Parser)]
struct AddClientScope {
    #[clap(short, long)]
    id: String,
    #[clap(short, long)]
    scope: String,
}

#[derive(Parser)]
struct DeleteClientScope {
    #[clap(short, long)]
    id: String,
    #[clap(short, long)]
    scope: String,
}

fn get_database(uri: &str) -> PgConnection {
    PgConnection::establish(uri)
	.expect("Failed to connect to database")
}

fn get_hasher(secret: &str) -> HashingService {
    HashingService::with_secret_key(secret.to_string())
}

fn create_client(c: &CreateClient, opts: &Options) {
    use schema::clients::dsl::clients;

    let db = get_database(&opts.database_url);
    let hasher = get_hasher(&opts.hash_secret);

    let secret_hash = hasher
        .hash(&ClientSecret(c.secret.to_string()))
        .expect("Failed to hash password")
        .0;

    let model = models::Client {
	client_id: c.id.to_string(),
	name: c.name.to_string(),
	secret_hash
    };

    diesel::insert_into(clients)
	.values(model)
	.execute(&db)
	.expect("Failed to add client");
}

fn delete_client(c: &DeleteClient, opts: &Options) {
    use schema::clients::dsl::clients;
    
    let db = get_database(&opts.database_url);

    diesel::delete(
	clients.find(&c.id)
    )
	.execute(&db)
	.expect("Failed to delete client");
}

fn add_client_uri(c: &AddClientUri, opts: &Options) {
    use schema::uris::dsl::uris;
    
    let db = get_database(&opts.database_url);

    let model = models::Uri {
        client_id: c.id.to_string(),
        uri: c.uri.to_string()
    };

    diesel::insert_into(uris)
	.values(model)
	.execute(&db)
	.expect("Failed to add uri");
}

fn delete_client_uri(c: &DeleteClientUri, opts: &Options) {
    use schema::uris::dsl::uris;
    
    let db = get_database(&opts.database_url);

    diesel::delete(
	uris.find((&c.id, &c.uri))
    )
	.execute(&db)
	.expect("Failed to delete uri");
}

fn add_client_scope(c: &AddClientScope, opts: &Options) {
    use schema::client_scopes::dsl::client_scopes;
    
    let db = get_database(&opts.database_url);
    let scopes = Scope::from_delimited_parts(&c.scope)
	.as_parts();

    for scope in scopes {
	let model = models::ClientScope {
            client_id: c.id.to_string(),
            scope: scope.to_string()
	};

	diesel::insert_into(client_scopes)
	    .values(model)
	    .execute(&db)
	    .expect("Failed to add client scope");
    }
}

fn delete_client_scope(c: &DeleteClientScope, opts: &Options) {
    use schema::client_scopes::dsl::client_scopes;
    
    let db = get_database(&opts.database_url);
    let scopes = Scope::from_delimited_parts(&c.scope)
	.as_parts();

    for scope in scopes {
	diesel::delete(
	    client_scopes.find((&c.id, scope))
	)
	    .execute(&db)
	    .expect("Failed to delete client scope");
    }
}

pub fn run_cli_action(opts: Options) {
    use SubCommand::*;

    match &opts.command {
        CreateClient(c) => create_client(c, &opts),
        DeleteClient(c) => delete_client(c, &opts),
        AddClientUri(c) => add_client_uri(c, &opts),
        DeleteClientUri(c) => delete_client_uri(c, &opts),
        AddClientScope(c) => add_client_scope(c, &opts),
        DeleteClientScope(c) => delete_client_scope(c, &opts)
    };
}
