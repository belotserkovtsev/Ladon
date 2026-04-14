CREATE TABLE IF NOT EXISTS domains (
    domain TEXT PRIMARY KEY,
    etld_plus_one TEXT,
    first_seen_at TEXT,
    last_seen_at TEXT,
    hit_count INTEGER NOT NULL DEFAULT 0,
    peer_count INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'new',
    score REAL NOT NULL DEFAULT 0,
    cooldown_until TEXT,
    last_probe_id INTEGER
);

CREATE TABLE IF NOT EXISTS probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    dns_ok INTEGER,
    tcp_ok INTEGER,
    tls_ok INTEGER,
    http_ok INTEGER,
    resolved_ips_json TEXT,
    failure_reason TEXT,
    latency_ms INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hot_entries (
    domain TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manual_entries (
    domain TEXT PRIMARY KEY,
    list_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
