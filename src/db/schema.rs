table! {
    challenges (id) {
        id -> Text,
        req -> Text,
        ok -> Bool,
        subject -> Nullable<Text>,
        scope -> Text,
        invalid_after -> Int8,
    }
}

table! {
    client_scopes (client_id, scope) {
        client_id -> Text,
        scope -> Text,
    }
}

table! {
    clients (client_id) {
        client_id -> Text,
        secret_hash -> Text,
        name -> Text,
    }
}

table! {
    codes (code) {
        client_id -> Text,
        code -> Text,
        req -> Text,
        invalid_after -> Int8,
        subject -> Text,
    }
}

table! {
    consent_scopes (client_id, subject, scope) {
        client_id -> Text,
        subject -> Text,
        scope -> Text,
    }
}

table! {
    persistent_seeds (persistent_seed_id) {
        persistent_seed_id -> Text,
        subject -> Text,
        auth_data -> Text,
        client_id -> Text,
    }
}

table! {
    refresh_tokens (refresh_token_id) {
        refresh_token_id -> Text,
        invalid_after -> Int8,
        persistent_seed_id -> Text,
    }
}

table! {
    uris (client_id, uri) {
        client_id -> Text,
        uri -> Text,
    }
}

joinable!(persistent_seeds -> clients (client_id));
joinable!(refresh_tokens -> persistent_seeds (persistent_seed_id));

allow_tables_to_appear_in_same_query!(
    challenges,
    client_scopes,
    clients,
    codes,
    consent_scopes,
    persistent_seeds,
    refresh_tokens,
    uris,
);
