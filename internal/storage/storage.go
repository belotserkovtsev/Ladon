// Package storage is the SQLite access layer for ladon.
package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"github.com/belotserkovtsev/ladon/internal/etld"
	"github.com/belotserkovtsev/ladon/internal/migrate"
	"modernc.org/sqlite"
)

// Store owns two *sql.DB handles pointing at the same SQLite file. SQLite has
// one writer slot at the engine layer; funnelling all Go writes through a
// single-connection pool (wdb) aligns our concurrency model with SQLite's
// instead of relying on busy_timeout to absorb contention — an N-conn pool
// under burst produces SQLITE_BUSY because any given writer can wait longer
// than the timeout. Reads go through a default-sized pool (rdb) and overlap
// naturally with the writer thanks to WAL's snapshot isolation: a reader sees
// the last committed state without blocking on the writer or being blocked
// by it.
type Store struct {
	rdb *sql.DB // read pool: default sizing, WAL readers run concurrently with the writer
	wdb *sql.DB // write pool: capped at one conn so all writes serialize in Go
}

// perConnPragmas runs on every new connection either pool opens.
// journal_mode=WAL is database-level (lives in the file header) so we set it
// via the DSN once; the pragmas here are per-connection and must be applied
// on each fresh conn.
var perConnPragmas = []string{
	`PRAGMA busy_timeout = 5000`,
	`PRAGMA foreign_keys = ON`,
}

// dsnConnector adapts modernc.org/sqlite's driver.Driver (which does not
// implement driver.DriverContext) to the driver.Connector interface that
// sql.OpenDB needs.
type dsnConnector struct {
	drv driver.Driver
	dsn string
}

func (c *dsnConnector) Connect(_ context.Context) (driver.Conn, error) {
	return c.drv.Open(c.dsn)
}

func (c *dsnConnector) Driver() driver.Driver { return c.drv }

// pragmaConnector wraps a driver.Connector and runs the PRAGMAs on each new
// connection before handing it to the pool.
type pragmaConnector struct {
	base    driver.Connector
	pragmas []string
}

func (p *pragmaConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := p.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	execer, ok := conn.(driver.ExecerContext)
	if !ok {
		conn.Close()
		return nil, errors.New("storage: driver.Conn does not implement ExecerContext")
	}
	for _, stmt := range p.pragmas {
		if _, err := execer.ExecContext(ctx, stmt, nil); err != nil {
			conn.Close()
			return nil, fmt.Errorf("storage: apply %q: %w", stmt, err)
		}
	}
	return conn, nil
}

func (p *pragmaConnector) Driver() driver.Driver { return p.base.Driver() }

// openPool builds one *sql.DB wrapped by the pragma connector, pinging eagerly
// so a misconfigured driver or PRAGMA fails at startup rather than first query.
func openPool(path string) (*sql.DB, error) {
	connector := &pragmaConnector{
		base: &dsnConnector{
			drv: &sqlite.Driver{},
			dsn: path + "?_pragma=journal_mode(WAL)",
		},
		pragmas: perConnPragmas,
	}
	db := sql.OpenDB(connector)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func Open(path string) (*Store, error) {
	rdb, err := openPool(path)
	if err != nil {
		return nil, err
	}
	wdb, err := openPool(path)
	if err != nil {
		rdb.Close()
		return nil, err
	}
	// Cap the write pool at one connection. All calls routed through wdb
	// serialize in Go via sql.DB's internal queue; SQLite never sees two
	// Go connections competing for the writer slot, so SQLITE_BUSY becomes
	// structurally impossible rather than timeout-dependent.
	wdb.SetMaxOpenConns(1)
	return &Store{rdb: rdb, wdb: wdb}, nil
}

func (s *Store) Close() error {
	werr := s.wdb.Close()
	rerr := s.rdb.Close()
	if werr != nil {
		return werr
	}
	return rerr
}

// Init brings the database schema up to date and runs lightweight backfills. It
// is idempotent — safe to call on every startup — so both the init-db subcommand
// and the run daemon invoke it, and an already-current database is left untouched.
func (s *Store) Init(ctx context.Context) error {
	if err := migrate.Run(ctx, s.wdb, schema); err != nil {
		return err
	}
	// Backfill etld_plus_one for any rows that pre-date the column population.
	_, err := s.BackfillETLDPlusOne(ctx)
	return err
}

// BackfillETLDPlusOne fills etld_plus_one for rows where it is NULL or empty.
// Returns the number of rows updated.
func (s *Store) BackfillETLDPlusOne(ctx context.Context) (int, error) {
	rows, err := s.wdb.QueryContext(ctx,
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
		if _, err := s.wdb.ExecContext(ctx,
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
func (s *Store) UpsertDomain(ctx context.Context, domain string, seenAt time.Time) error {
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	ts := formatTime(seenAt)

	tx, err := s.wdb.BeginTx(ctx, nil)
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
		_, err = tx.ExecContext(ctx, `
			INSERT INTO domains (domain, etld_plus_one, first_seen_at, last_seen_at, hit_count, state)
			VALUES (?, ?, ?, ?, 1, 'new')
		`, domain, etld.Compute(domain), ts, ts)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ProbeResult is the shape accepted by InsertProbe. It carries the raw probe
// observations; the cycle verdict is stamped separately via SetProbeVerdict
// once decision/exit-compare has run.
type ProbeResult struct {
	Domain        string
	DNSOK         *bool
	TCPOK         *bool
	TLSOK         *bool
	HTTPOK        *bool
	FailureReason string
}

func (s *Store) InsertProbe(ctx context.Context, r ProbeResult, createdAt time.Time) (int64, error) {
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	res, err := s.wdb.ExecContext(ctx, `
		INSERT INTO probes (
			domain, dns_ok, tcp_ok, tls_ok, http_ok, failure_reason, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		r.Domain,
		boolPtrToNullInt(r.DNSOK),
		boolPtrToNullInt(r.TCPOK),
		boolPtrToNullInt(r.TLSOK),
		boolPtrToNullInt(r.HTTPOK),
		nullableString(r.FailureReason),
		formatTime(createdAt),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetProbeVerdict stamps the final cycle verdict onto a probe row (the local
// anchor row of an authoritative batch cycle). Counted later by the scorer.
func (s *Store) SetProbeVerdict(ctx context.Context, id int64, verdict string) error {
	_, err := s.wdb.ExecContext(ctx,
		`UPDATE probes SET verdict = ? WHERE id = ?`, verdict, id)
	return err
}

// Domain is a row from the domains table.
type Domain struct {
	Domain        string
	ETLDPlusOne   string
	FirstSeenAt   string
	LastSeenAt    string
	HitCount      int
	State         string
	CooldownUntil string
}

// UpsertDNSObservation records that `ip` was seen as an answer for `domain`.
// If the (domain, ip) pair already exists, bumps hit_count and last_seen_at.
func (s *Store) UpsertDNSObservation(ctx context.Context, domain, ip string, seenAt time.Time) error {
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	ts := formatTime(seenAt)
	_, err := s.wdb.ExecContext(ctx, `
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
	rows, err := s.rdb.QueryContext(ctx,
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
	err := s.rdb.QueryRowContext(ctx,
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

// FamilyConfirmed reports whether at least `threshold` domains sharing this
// eTLD+1 are confirmed blocked (state hot or cache). The count is capped at the
// threshold so a big CDN family doesn't scan thousands of rows. Used to decide
// when a family is trusted enough to expand its IPs and stop probing new members.
func (s *Store) FamilyConfirmed(ctx context.Context, etldPlusOne string, threshold int) (bool, error) {
	if etldPlusOne == "" || threshold <= 0 {
		return false, nil
	}
	var n int
	err := s.rdb.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT 1 FROM domains
			WHERE etld_plus_one = ? AND state IN ('hot', 'cache')
			LIMIT ?
		)`, etldPlusOne, threshold).Scan(&n)
	if err != nil {
		return false, err
	}
	return n >= threshold, nil
}

// MarkCovered flips a domain from 'new' to 'covered': it belongs to a confirmed
// blocked family and is routed via the family's eTLD+1 IP expansion, so it is
// never probed individually (both probe-candidate queries exclude 'covered').
// Only 'new' rows are touched, so the hot/cache anchors that keep the family
// confirmed are never demoted. Returns whether a row was flipped.
func (s *Store) MarkCovered(ctx context.Context, domain string) (bool, error) {
	res, err := s.wdb.ExecContext(ctx,
		`UPDATE domains SET state = 'covered' WHERE domain = ? AND state = 'new'`, domain)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PromoteCache upserts a cache_entries row and flips the domain's state to
// 'cache'. Cache entries have no TTL — they persist until a re-probe reverses
// them or the operator clears the row.
func (s *Store) PromoteCache(ctx context.Context, domain, reason string, at time.Time) error {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ts := formatTime(at)
	tx, err := s.wdb.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Fold the hot_entries reason (the DPI detail, e.g. "local:tls13_block|…")
	// into the cache reason before we drop the hot row, so the audit trail
	// survives the tier transition. A missing/empty hot reason leaves the
	// caller's reason (e.g. "repeated_block") as-is.
	fullReason := reason
	var hotReason sql.NullString
	if err := tx.QueryRowContext(ctx,
		`SELECT reason FROM hot_entries WHERE domain = ?`, domain).Scan(&hotReason); err == nil &&
		hotReason.Valid && hotReason.String != "" {
		fullReason = reason + " (" + hotReason.String + ")"
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cache_entries (domain, promoted_at, reason)
		VALUES (?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET promoted_at = excluded.promoted_at, reason = excluded.reason
	`, domain, ts, nullableString(fullReason)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE domains SET state = 'cache' WHERE domain = ?`, domain); err != nil {
		return err
	}
	// Promotion moves the domain from the hot tier (24h TTL) to the durable
	// cache tier — drop the now-redundant hot_entries row. cache_entries already
	// keeps it in the ipset union; cache-state domains are never re-probed so the
	// row won't be recreated; and leaving it made the scorer re-promote the same
	// domain every cycle (ListHotEntries still returned it) and double-count it
	// toward computeDesiredIPs' eTLD-expansion gate. With this, a domain sits in
	// exactly one tier (hot XOR cache).
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM hot_entries WHERE domain = ?`, domain); err != nil {
		return err
	}
	return tx.Commit()
}

// ListCacheEntries returns all cached domains.
func (s *Store) ListCacheEntries(ctx context.Context) ([]string, error) {
	rows, err := s.rdb.QueryContext(ctx, `SELECT domain FROM cache_entries ORDER BY domain`)
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

// CountBlockedVerdicts returns how many authoritative probe cycles for
// `domain` since `since` concluded the domain is blocked (verdict='blocked').
// Counting the decision-level verdict — not raw transport failure — is what
// lets differential/L7 blocks (tls13_block, http_cutoff, …) accrue toward a
// hot → cache promotion. Those leave tcp_ok/tls_ok=1, so the old transport
// check never counted them and such domains never graduated.
func (s *Store) CountBlockedVerdicts(ctx context.Context, domain string, since time.Time) (int, error) {
	ts := formatTime(since)
	var n int
	err := s.rdb.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM probes
		WHERE domain = ? AND created_at >= ? AND verdict = 'blocked'
	`, domain, ts).Scan(&n)
	return n, err
}

// UpsertManual adds a row to manual_entries. listName is 'allow' or 'deny'.
func (s *Store) UpsertManual(ctx context.Context, domain, listName string) error {
	_, err := s.wdb.ExecContext(ctx, `
		INSERT INTO manual_entries (domain, list_name, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET list_name = excluded.list_name
	`, domain, listName, formatTime(time.Now().UTC()))
	return err
}

// ListManualByList returns domains in a given list.
func (s *Store) ListManualByList(ctx context.Context, listName string) ([]string, error) {
	rows, err := s.rdb.QueryContext(ctx,
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
	err := s.rdb.QueryRowContext(ctx, q, args...).Scan(&one)
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
	rows, err := s.rdb.QueryContext(ctx, `
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
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT domain, COALESCE(etld_plus_one, ''), COALESCE(first_seen_at, ''),
		       COALESCE(last_seen_at, ''), hit_count, state,
		       COALESCE(cooldown_until, '')
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
			&d.HitCount, &d.State, &d.CooldownUntil,
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
	_, err := s.wdb.ExecContext(ctx,
		`UPDATE domains SET state = ?, cooldown_until = ? WHERE domain = ?`,
		state, cd, domain)
	return err
}

// UpsertHotEntry adds or refreshes a hot_entries row.
func (s *Store) UpsertHotEntry(ctx context.Context, domain, reason string, expiresAt time.Time) error {
	now := formatTime(time.Now().UTC())
	_, err := s.wdb.ExecContext(ctx, `
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
	rows, err := s.rdb.QueryContext(ctx,
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
	res, err := s.wdb.ExecContext(ctx, `DELETE FROM hot_entries WHERE expires_at <= ?`, ts)
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
	res, err := s.wdb.ExecContext(ctx, `DELETE FROM hot_entries WHERE domain = ?`, domain)
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
	return deleteWithOptionalBefore(ctx, s.wdb, "cache_entries", "promoted_at", before)
}

// PruneHot deletes hot_entries rows. See PruneCache for semantics.
func (s *Store) PruneHot(ctx context.Context, before time.Time) (int64, error) {
	return deleteWithOptionalBefore(ctx, s.wdb, "hot_entries", "created_at", before)
}

// PruneProbes deletes probes rows. See PruneCache for semantics.
func (s *Store) PruneProbes(ctx context.Context, before time.Time) (int64, error) {
	return deleteWithOptionalBefore(ctx, s.wdb, "probes", "created_at", before)
}

// PruneDNSCache deletes dns_cache rows by last_seen_at. See PruneCache for
// zero-time semantics. Reads already ignore rows older than DNSFreshness, so
// deleting stale observations is a pure space reclaim with no behavior change.
func (s *Store) PruneDNSCache(ctx context.Context, before time.Time) (int64, error) {
	return deleteWithOptionalBefore(ctx, s.wdb, "dns_cache", "last_seen_at", before)
}

// Checkpoint runs a TRUNCATE-mode WAL checkpoint: it merges the -wal file back
// into the main database and resets it to zero length. The long-lived read pool
// keeps WAL pages referenced, which prevents SQLite's passive auto-checkpoint
// from truncating, so the engine calls this periodically to bound WAL growth.
// Best-effort: if a reader is mid-transaction SQLite returns busy and leaves the
// WAL in place — the next tick retries.
func (s *Store) Checkpoint(ctx context.Context) error {
	rows, err := s.wdb.QueryContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	if err != nil {
		return err
	}
	return rows.Close()
}

// DeleteDeniedDomains removes rows from the domains table whose domain or
// eTLD+1 matches an entry in manual_entries with list_name='deny'. These
// domains should never appear in any engine-tracked table — the tailer skips
// their dnsmasq events at ingest via IsInDenyList, so any rows that predate
// a deny-list addition are orphans that shouldn't linger. Called during the
// prune subcommand so operators get a clean domains table alongside the
// hot/cache/probes cleanup they already asked for. Returns rows deleted.
func (s *Store) DeleteDeniedDomains(ctx context.Context) (int64, error) {
	res, err := s.wdb.ExecContext(ctx, `
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
	res, err := s.wdb.ExecContext(ctx, `
		UPDATE domains
		SET state = 'new', cooldown_until = NULL
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
	return countWithOptionalBefore(ctx, s.rdb, "cache_entries", "promoted_at", before)
}
func (s *Store) CountHot(ctx context.Context, before time.Time) (int64, error) {
	return countWithOptionalBefore(ctx, s.rdb, "hot_entries", "created_at", before)
}
func (s *Store) CountProbes(ctx context.Context, before time.Time) (int64, error) {
	return countWithOptionalBefore(ctx, s.rdb, "probes", "created_at", before)
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
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT domain, COALESCE(etld_plus_one, ''), COALESCE(first_seen_at, ''),
		       COALESCE(last_seen_at, ''), hit_count, state,
		       COALESCE(cooldown_until, '')
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
			&d.HitCount, &d.State, &d.CooldownUntil,
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
