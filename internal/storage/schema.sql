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
    list_name TEXT NOT NULL,   -- 'allow' or 'deny'
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_manual_entries_list ON manual_entries(list_name);

-- cache_entries is hot's older, steadier sibling: promoted only after
-- repeated probe-failure evidence accumulates. No TTL; entries stay until
-- an explicit re-probe reverses them (Phase 7) or operator deletes.
CREATE TABLE IF NOT EXISTS cache_entries (
    domain TEXT PRIMARY KEY,
    promoted_at TEXT NOT NULL,
    reason TEXT
);

-- Passive observation of upstream DNS replies: which IPs dnsmasq actually
-- handed out for a domain. We don't overwrite, we accumulate — CDNs rotate
-- IPs and we want the full set seen recently. (domain, ip) is unique; the
-- last_seen_at column tells us how fresh an IP observation is.
CREATE TABLE IF NOT EXISTS dns_cache (
    domain TEXT NOT NULL,
    ip TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (domain, ip)
);
CREATE INDEX IF NOT EXISTS idx_dns_cache_domain ON dns_cache(domain);
CREATE INDEX IF NOT EXISTS idx_dns_cache_last_seen ON dns_cache(last_seen_at);
