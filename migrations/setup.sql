CREATE TABLE uris(client_id TEXT NOT NULL, uri TEXT NOT NULL);
CREATE TABLE clients(client_id TEXT NOT NULL PRIMARY KEY, secret_hash TEXT NOT NULL);
CREATE TABLE codes(client_id TEXT NOT NULL, code TEXT NOT NULL, req TEXT NOT NULL, invalid_after INTEGER, subject TEXT NOT NULL);
CREATE TABLE client_scopes(client_id TEXT NOT NULL, scope TEXT NOT NULL);
CREATE TABLE challenges(
       id TEXT NOT NULL PRIMARY KEY,
       req TEXT NOT NULL,
       ok BOOLEAN NOT NULL,
       subject TEXT,
       scope TEXT NOT NULL,
       invalid_after INTEGER NOT NULL
);
CREATE TABLE persistent_seeds(
       persistent_seed_id TEXT NOT NULL PRIMARY KEY,
       subject TEXT NOT NULL,
       auth_data TEXT NOT NULL,
       client_id TEXT NOT NULL REFERENCES clients(client_id)
);
CREATE TABLE refresh_tokens(
       refresh_token_id TEXT NOT NULL PRIMARY KEY,
       invalid_after INTEGER NOT NULL,
       persistent_seed_id TEXT NOT NULL REFERENCES persistent_seeds(persistent_seed_id)
);
CREATE INDEX refresh_token_seeds ON refresh_tokens(persistent_seed_id);
CREATE TABLE consent_scopes(
       client_id TEXT NOT NULL,
       subject TEXT NOT NULL,
       scope TEXT NOT NULL,
       PRIMARY KEY (client_id, subject, scope)
);
