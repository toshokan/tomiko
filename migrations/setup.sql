CREATE TABLE uris(client_id TEXT NOT NULL, uri TEXT NOT NULL);
CREATE TABLE clients(client_id TEXT NOT NULL UNIQUE, secret_hash TEXT NOT NULL);
CREATE TABLE codes(client_id TEXT NOT NULL, code TEXT NOT NULL, req TEXT NOT NULL, invalid_after INTEGER, subject TEXT NOT NULL);
CREATE TABLE client_scopes(client_id TEXT NOT NULL, scope TEXT NOT NULL);
CREATE TABLE challenges(id TEXT NOT NULL PRIMARY KEY, req TEXT NOT NULL, ok BOOLEAN NOT NULL, subject TEXT, scope TEXT);
