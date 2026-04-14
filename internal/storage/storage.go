// Package storage is the SQLite access layer for split-engine.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

// UpsertDomain records a domain observation. If the row exists, it bumps
// hit_count and last_seen_at; otherwise it inserts a new row in state='new'.
func (s *Store) UpsertDomain(ctx context.Context, domain, peer string, seenAt time.Time) error {
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	ts := formatTime(seenAt)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM domains WHERE domain = ?`, domain).Scan(&exists)
	switch err {
	case nil:
		_, err = tx.ExecContext(ctx,
			`UPDATE domains SET last_seen_at = ?, hit_count = hit_count + 1 WHERE domain = ?`,
			ts, domain)
	case sql.ErrNoRows:
		peerCount := 0
		if peer != "" {
			peerCount = 1
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO domains (domain, first_seen_at, last_seen_at, hit_count, peer_count, state)
			VALUES (?, ?, ?, 1, ?, 'new')
		`, domain, ts, ts, peerCount)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ProbeResult is the shape accepted by InsertProbe.
type ProbeResult struct {
	Domain        string
	DNSOK         *bool
	TCPOK         *bool
	TLSOK         *bool
	HTTPOK        *bool
	ResolvedIPs   []string
	FailureReason string
	LatencyMS     int
}

func (s *Store) InsertProbe(ctx context.Context, r ProbeResult, createdAt time.Time) (int64, error) {
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	ts := formatTime(createdAt)

	ips, err := json.Marshal(r.ResolvedIPs)
	if err != nil {
		return 0, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO probes (
			domain, dns_ok, tcp_ok, tls_ok, http_ok,
			resolved_ips_json, failure_reason, latency_ms, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		r.Domain,
		boolPtrToNullInt(r.DNSOK),
		boolPtrToNullInt(r.TCPOK),
		boolPtrToNullInt(r.TLSOK),
		boolPtrToNullInt(r.HTTPOK),
		string(ips),
		nullableString(r.FailureReason),
		r.LatencyMS,
		ts,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE domains SET last_probe_id = ? WHERE domain = ?`, id, r.Domain); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// Domain is a row from the domains table.
type Domain struct {
	Domain        string
	ETLDPlusOne   string
	FirstSeenAt   string
	LastSeenAt    string
	HitCount      int
	PeerCount     int
	State         string
	Score         float64
	CooldownUntil string
	LastProbeID   *int64
}

// ListProbeCandidates returns domains that are ready for a probe — eligible
// states, cooldown expired (or null). Ordered by oldest cooldown first, then
// most-recent observations first.
func (s *Store) ListProbeCandidates(ctx context.Context, limit int, now time.Time) ([]Domain, error) {
	ts := formatTime(now)
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain, COALESCE(etld_plus_one, ''), COALESCE(first_seen_at, ''),
		       COALESCE(last_seen_at, ''), hit_count, peer_count, state, score,
		       COALESCE(cooldown_until, ''), last_probe_id
		FROM domains
		WHERE state IN ('new', 'watch', 'hot')
		  AND (cooldown_until IS NULL OR cooldown_until <= ?)
		ORDER BY COALESCE(cooldown_until, first_seen_at) ASC, last_seen_at DESC
		LIMIT ?
	`, ts, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(
			&d.Domain, &d.ETLDPlusOne, &d.FirstSeenAt, &d.LastSeenAt,
			&d.HitCount, &d.PeerCount, &d.State, &d.Score,
			&d.CooldownUntil, &d.LastProbeID,
		); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetDomainState updates state and cooldown_until atomically.
func (s *Store) SetDomainState(ctx context.Context, domain, state string, cooldownUntil time.Time) error {
	var cd any
	if cooldownUntil.IsZero() {
		cd = nil
	} else {
		cd = formatTime(cooldownUntil)
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE domains SET state = ?, cooldown_until = ? WHERE domain = ?`,
		state, cd, domain)
	return err
}

// UpsertHotEntry adds or refreshes a hot_entries row.
func (s *Store) UpsertHotEntry(ctx context.Context, domain, reason string, expiresAt time.Time) error {
	now := formatTime(time.Now().UTC())
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO hot_entries (domain, expires_at, reason, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
		  expires_at = excluded.expires_at,
		  reason = excluded.reason
	`, domain, formatTime(expiresAt), reason, now)
	return err
}

// ListHotEntries returns currently-live hot_entries (expires_at > now).
func (s *Store) ListHotEntries(ctx context.Context, now time.Time) ([]string, error) {
	ts := formatTime(now)
	rows, err := s.db.QueryContext(ctx,
		`SELECT domain FROM hot_entries WHERE expires_at > ? ORDER BY domain`, ts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ExpireHotEntries deletes rows where expires_at <= now. Returns deleted count.
func (s *Store) ExpireHotEntries(ctx context.Context, now time.Time) (int64, error) {
	ts := formatTime(now)
	res, err := s.db.ExecContext(ctx, `DELETE FROM hot_entries WHERE expires_at <= ?`, ts)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) ListRecentDomains(ctx context.Context, limit int) ([]Domain, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain, COALESCE(etld_plus_one, ''), COALESCE(first_seen_at, ''),
		       COALESCE(last_seen_at, ''), hit_count, peer_count, state, score,
		       COALESCE(cooldown_until, ''), last_probe_id
		FROM domains ORDER BY last_seen_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(
			&d.Domain, &d.ETLDPlusOne, &d.FirstSeenAt, &d.LastSeenAt,
			&d.HitCount, &d.PeerCount, &d.State, &d.Score,
			&d.CooldownUntil, &d.LastProbeID,
		); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func boolPtrToNullInt(b *bool) any {
	if b == nil {
		return nil
	}
	if *b {
		return 1
	}
	return 0
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
