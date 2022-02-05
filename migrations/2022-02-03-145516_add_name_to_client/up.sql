-- Your SQL goes here
ALTER TABLE clients
ADD COLUMN name TEXT;

UPDATE clients
SET name = clients.client_id
WHERE name IS NULL;

ALTER TABLE clients
ALTER COLUMN name SET NOT NULL;
