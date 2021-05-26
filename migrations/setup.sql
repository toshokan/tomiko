CREATE TABLE uris(client_id TEXT NOT NULL, uri TEXT NOT NULL);
CREATE TABLE clients(client_id TEXT NOT NULL UNIQUE, secret_hash TEXT NOT NULL);
CREATE TABLE codes(client_id TEXT NOT NULL, code TEXT NOT NULL, state TEXT, uri TEXT NOT NULL, scope TEXT, invalid_after INTEGER);
CREATE TABLE client_scopes(client_id TEXT NOT NULL, scope TEXT NOT NULL);
CREATE TABLE challenges(id TEXT NOT NULL PRIMARY KEY, client_id TEXT NOT NULL, uri TEXT NOT NULL, scope TEXT NOT NULL, state TEXT, ok BOOLEAN NOT NULL);
