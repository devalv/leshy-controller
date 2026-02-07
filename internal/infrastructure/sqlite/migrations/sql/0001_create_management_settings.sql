CREATE TABLE IF NOT EXISTS management_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    token TEXT NOT NULL,
    guarded_ports_range TEXT NOT NULL,
    iface TEXT NOT NULL,
    updated_at_unix INTEGER NOT NULL
);
