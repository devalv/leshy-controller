CREATE TABLE IF NOT EXISTS management_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    jwks_url TEXT NOT NULL,
    required_scope TEXT NOT NULL,
    guarded_ports_range TEXT NOT NULL,
    iface TEXT NOT NULL,
    handshake_window_sec INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);
