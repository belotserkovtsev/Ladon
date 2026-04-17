// Package storage is the SQLite access layer for ladon.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/belotserkovtsev/ladon/internal/etld"
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
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return err
	}
	// Backfill etld_plus_one for any rows that pre-date the column population.
	_, err := s.BackfillETLDPlusOne(ctx)
	return err
}

// BackfillETLDPlusOne fills etld_plus_one for rows where it is NULL or empty.
// Returns the number of rows updated.
func (s *Store) BackfillETLDPlusOne(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT domain FROM domains WHERE etld_plus_one IS NULL OR etld_plus_one = ''`)
	if err != nil {
		return 0, err
	}
	var todo []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			rows.Close()
			return 0, err
		}
		todo = append(todo, d)
	}
	rows.Close()

	updated := 0
	for _, d := range todo {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE domains SET etld_plus_one = ? WHERE domain = ?`,
			etld.Compute(d), d); err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
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
			INSERT INTO domains (domain, etld_plus_one, first_seen_at, last_seen_at, hit_count, peer_count, state)
			VALUES (?, ?, ?, ?, 1, ?, 'new')
		`, domain, etld.Compute(domain), ts, ts, peerCount)
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

// UpsertDNSObservation records that `ip` was seen as an answer for `domain`.
// If the (domain, ip) pair already exists, bumps hit_count and last_seen_at.
func (s *Store) UpsertDNSObservation(ctx context.Context, domain, ip string, seenAt time.Time) error {
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	ts := formatTime(seenAt)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO dns_cache (domain, ip, first_seen_at, last_seen_at, hit_count)
		VALUES (?, ?, ?, ?, 1)
		ON CONFLICT(domain, ip) DO UPDATE SET
		  last_seen_at = excluded.last_seen_at,
		  hit_count = dns_cache.hit_count + 1
	`, domain, ip, ts, ts)
	return err
}

// LookupIPs returns the IPs recently observed for a domain, freshest first.
func (s *Store) LookupIPs(ctx context.Context, domain string, freshSince time.Time) ([]string, error) {
	ts := formatTime(freshSince)
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip FROM dns_cache WHERE domain = ? AND last_seen_at >= ? ORDER BY last_seen_at DESC`,
		domain, ts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// ProbeEligible reports whether domain is ready for an immediate probe —
// i.e. in a probeable state with no active cooldown. Used by the inline
// fast-path in the tailer to avoid duplicate probes when the worker has
// already (or recently) probed the same domain.
func (s *Store) ProbeEligible(ctx context.Context, domain string, now time.Time) (bool, error) {
	ts := formatTime(now)
	var state, cd sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT state, cooldown_until FROM domains WHERE domain = ?`, domain).Scan(&state, &cd)
	if err == sql.ErrNoRows {
		// Unknown domain — definitely eligible (UpsertDomain is separate).
		return true, nil
	}
	if err != nil {
		return false, err
	}
	switch state.String {
	case "new", "watch", "hot":
	default:
		return false, nil
	}
	if !cd.Valid || cd.String == "" {
		return true, nil
	}
	return cd.String <= ts, nil
}

// PromoteCache upserts a cache_entries row and flips the domain's state to
// 'cache'. Cache entries have no TTL — they persist until a re-probe reverses
// them or the operator clears the row.
func (s *Store) PromoteCache(ctx context.Context, domain, reason string, at time.Time) error {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ts := formatTime(at)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cache_entries (domain, promoted_at, reason)
		VALUES (?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET promoted_at = excluded.promoted_at, reason = excluded.reason
	`, domain, ts, nullableString(reason)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE domains SET state = 'cache' WHERE domain = ?`, domain); err != nil {
		return err
	}
	return tx.Commit()
}

// ListCacheEntries returns all cached domains.
func (s *Store) ListCacheEntries(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM cache_entries ORDER BY domain`)
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

// CountFailingProbes returns how many probes for `domain` since `since`
// recorded a failure (TCP or TLS not OK). Used by scorer to decide when
// repeated evidence warrants a hot → cache promotion.
func (s *Store) CountFailingProbes(ctx context.Context, domain string, since time.Time) (int, error) {
	ts := formatTime(since)
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM probes
		WHERE domain = ? AND created_at >= ? AND (COALESCE(tcp_ok, 0) = 0 OR COALESCE(tls_ok, 0) = 0)
	`, domain, ts).Scan(&n)
	return n, err
}

// UpsertManual adds a row to manual_entries. listName is 'allow' or 'deny'.
func (s *Store) UpsertManual(ctx context.Context, domain, listName string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO manual_entries (domain, list_name, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET list_name = excluded.list_name
	`, domain, listName, formatTime(time.Now().UTC()))
	return err
}

// ListManualByList returns domains in a given list.
func (s *Store) ListManualByList(ctx context.Context, listName string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT domain FROM manual_entries WHERE list_name = ? ORDER BY domain`, listName)
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

// IsInDenyList reports whether domain (or its eTLD+1, if different) is in
// the manual deny list. Callers should use this at ingest time to short-
// circuit noisy probing of intentionally-excluded destinations.
func (s *Store) IsInDenyList(ctx context.Context, domain, etldPlusOne string) (bool, error) {
	args := []any{domain}
	q := `SELECT 1 FROM manual_entries WHERE list_name = 'deny' AND domain = ?`
	if etldPlusOne != "" && etldPlusOne != domain {
		q += ` OR (list_name = 'deny' AND domain = ?)`
		args = append(args, etldPlusOne)
	}
	q += ` LIMIT 1`
	var one int
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// LookupIPsByETLD returns distinct IPs observed for any subdomain of etld+1.
// Used by ipset-syncer to expand a single hot domain to the CDN family —
// Meta's `netseer` UUID subdomains, for instance, all share fbcdn.net IPs.
func (s *Store) LookupIPsByETLD(ctx context.Context, etldPlusOne string, freshSince time.Time) ([]string, error) {
	ts := formatTime(freshSince)
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT c.ip
		FROM dns_cache c
		JOIN domains d ON d.domain = c.domain
		WHERE d.etld_plus_one = ? AND c.last_seen_at >= ?
		ORDER BY c.last_seen_at DESC
	`, etldPlusOne, ts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// ListProbeCandidates returns domains that are ready for a probe — eligible
// states, cooldown expired (or null), and not matched by the manual deny list.
// The deny filter mirrors IsInDenyList semantics (exact domain OR eTLD+1 in
// manual_entries with list_name='deny'). Without this filter, a denied domain
// that already lives in the domains table (ingested before the deny entry was
// added, or flipped to 'new' by ResetOrphanedDomains after a prune) would be
// probed by the batch worker and re-populate hot_entries — bypassing the
// tailer-level deny check at engine.go:253.
// Ordered by oldest cooldown first, then most-recent observations first.
func (s *Store) ListProbeCandidates(ctx context.Context, limit int, now time.Time) ([]Domain, error) {
	ts := formatTime(now)
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain, COALESCE(etld_plus_one, ''), COALESCE(first_seen_at, ''),
		       COALESCE(last_seen_at, ''), hit_count, peer_count, state, score,
		       COALESCE(cooldown_until, ''), last_probe_id
		FROM domains
		WHERE state IN ('new', 'watch', 'hot')
		  AND (cooldown_until IS NULL OR cooldown_until <= ?)
		  AND domain NOT IN (SELECT domain FROM manual_entries WHERE list_name = 'deny')
		  AND (etld_plus_one IS NULL OR etld_plus_one = ''
		       OR etld_plus_one NOT IN (SELECT domain FROM manual_entries WHERE list_name = 'deny'))
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

// DeleteHotEntry removes one row by domain. Used when a fresher probe overrules
// an earlier Hot verdict (e.g. exit-compare validator says the local fail was
// methodological — domain shouldn't sit in ipset for 24h on a stale opinion).
// Returns true if a row was deleted.
func (s *Store) DeleteHotEntry(ctx context.Context, domain string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM hot_entries WHERE domain = ?`, domain)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PruneCache deletes cache_entries rows. Pass a zero time to delete all, or a
// specific cutoff to only delete rows promoted before it. Operator-triggered
// cleanup (ladon prune -cache).
func (s *Store) PruneCache(ctx context.Context, before time.Time) (int64, error) {
	return deleteWithOptionalBefore(ctx, s.db, "cache_entries", "promoted_at", before)
}

// PruneHot deletes hot_entries rows. See PruneCache for semantics.
func (s *Store) PruneHot(ctx context.Context, before time.Time) (int64, error) {
	return deleteWithOptionalBefore(ctx, s.db, "hot_entries", "created_at", before)
}

// PruneProbes deletes probes rows. See PruneCache for semantics.
func (s *Store) PruneProbes(ctx context.Context, before time.Time) (int64, error) {
	return deleteWithOptionalBefore(ctx, s.db, "probes", "created_at", before)
}

// DeleteDeniedDomains removes rows from the domains table whose domain or
// eTLD+1 matches an entry in manual_entries with list_name='deny'. These
// domains should never appear in any engine-tracked table — the tailer skips
// their dnsmasq events at ingest via IsInDenyList, so any rows that predate
// a deny-list addition are orphans that shouldn't linger. Called during the
// prune subcommand so operators get a clean domains table alongside the
// hot/cache/probes cleanup they already asked for. Returns rows deleted.
func (s *Store) DeleteDeniedDomains(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM domains
		WHERE domain IN (SELECT domain FROM manual_entries WHERE list_name = 'deny')
		   OR (etld_plus_one IS NOT NULL AND etld_plus_one != ''
		       AND etld_plus_one IN (SELECT domain FROM manual_entries WHERE list_name = 'deny'))
	`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ResetOrphanedDomains flips `state` back to 'new' and clears cooldown_until
// for domains no longer backed by a hot_entries or cache_entries row. Called
// after a prune to make sure those domains can be re-probed from scratch
// instead of sitting in a stale terminal state.
func (s *Store) ResetOrphanedDomains(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE domains
		SET state = 'new', cooldown_until = NULL, last_probe_id = NULL
		WHERE state IN ('hot', 'cache', 'ignore')
		  AND domain NOT IN (SELECT domain FROM hot_entries)
		  AND domain NOT IN (SELECT domain FROM cache_entries)
	`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountCache, CountHot, CountProbes are dry-run companions to the Prune*
// helpers — same WHERE clause, no mutation. Used by `ladon prune -dry-run`.
func (s *Store) CountCache(ctx context.Context, before time.Time) (int64, error) {
	return countWithOptionalBefore(ctx, s.db, "cache_entries", "promoted_at", before)
}
func (s *Store) CountHot(ctx context.Context, before time.Time) (int64, error) {
	return countWithOptionalBefore(ctx, s.db, "hot_entries", "created_at", before)
}
func (s *Store) CountProbes(ctx context.Context, before time.Time) (int64, error) {
	return countWithOptionalBefore(ctx, s.db, "probes", "created_at", before)
}

// deleteWithOptionalBefore is the common shape of the three prune helpers.
// Table/column names are trusted (hardcoded in callers) — no interpolation of
// user input.
func deleteWithOptionalBefore(ctx context.Context, db *sql.DB, table, tsColumn string, before time.Time) (int64, error) {
	var res sql.Result
	var err error
	if before.IsZero() {
		res, err = db.ExecContext(ctx, `DELETE FROM `+table)
	} else {
		res, err = db.ExecContext(ctx, `DELETE FROM `+table+` WHERE `+tsColumn+` < ?`, formatTime(before))
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func countWithOptionalBefore(ctx context.Context, db *sql.DB, table, tsColumn string, before time.Time) (int64, error) {
	var n int64
	var err error
	if before.IsZero() {
		err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n)
	} else {
		err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE `+tsColumn+` < ?`, formatTime(before)).Scan(&n)
	}
	return n, err
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
