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
		// Name the path: the underlying driver reports a missing/unreachable
		// file as a cryptic "unable to open database file: out of memory (14)",
		// so without the path operators chase a phantom OOM (it's usually just a
		// wrong/relative -db pointing at a dir that doesn't exist).
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	wdb, err := openPool(path)
	if err != nil {
		rdb.Close()
		return nil, fmt.Errorf("open %q: %w", path, err)
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

// TimeLayout is the textual form every timestamp column (and runtime_meta time
// value) is stored in: UTC, second precision. Exported so out-of-package
// readers (doctor/status) parse the same shape the engine writes.
const TimeLayout = "2006-01-02 15:04:05"

// FormatTime renders a time in the storage layout (UTC).
func FormatTime(t time.Time) string {
	return t.UTC().Format(TimeLayout)
}

// ParseTime parses a storage-layout timestamp as UTC. The boolean is false for
// empty input (a NULL/absent value), distinct from a parse error.
func ParseTime(s string) (time.Time, bool, error) {
	if s == "" {
		return time.Time{}, false, nil
	}
	t, err := time.ParseInLocation(TimeLayout, s, time.UTC)
	if err != nil {
		return time.Time{}, false, err
	}
	return t, true, nil
}

func formatTime(t time.Time) string {
	return FormatTime(t)
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
// eTLD+1 are durably blocked (state 'cache'). Counting only cache — the stable
// anchors that are never converted to 'covered' — keeps confirmation steady as
// hot/new members get covered (counting hot too would let covering its own
// members drop the family below threshold and flap). The count is capped at the
// threshold so a big CDN family doesn't scan thousands of rows.
func (s *Store) FamilyConfirmed(ctx context.Context, etldPlusOne string, threshold int) (bool, error) {
	if etldPlusOne == "" || threshold <= 0 {
		return false, nil
	}
	var n int
	err := s.rdb.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT 1 FROM domains
			WHERE etld_plus_one = ? AND state = 'cache'
			LIMIT ?
		)`, etldPlusOne, threshold).Scan(&n)
	if err != nil {
		return false, err
	}
	return n >= threshold, nil
}

// MarkCovered flips a non-anchor member of a confirmed family to 'covered': it
// is routed via the family's eTLD+1 IP expansion, so it is never probed
// individually (both probe-candidate queries exclude 'covered'). Only 'new' and
// 'hot' rows are touched — never 'cache' (the anchors that keep the family
// confirmed). A flipped 'hot' member also sheds its hot_entries row, leaving it
// in exactly one tier. Returns whether a row was flipped.
func (s *Store) MarkCovered(ctx context.Context, domain string) (bool, error) {
	tx, err := s.wdb.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE domains SET state = 'covered' WHERE domain = ? AND state IN ('new', 'hot')`, domain)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, tx.Commit() // anchor (cache) or already covered — nothing to do
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM hot_entries WHERE domain = ?`, domain); err != nil {
		return false, err
	}
	return true, tx.Commit()
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

// ListBlockedDomains returns every domain ladon currently judges blocked,
// sorted. That is the three states routed through the tunnel: 'hot' (a probe
// said so and the verdict is still fresh), 'cache' (it kept saying so long
// enough to stick) and 'covered' (a member of a site confirmed as a whole).
//
// Deliberately domains rather than addresses: this is what the verdict is
// about, it survives the addresses rotating underneath, and it is the unit
// every consumer outside ladon speaks — a proxy's routing rules, an
// in-place bypass's list, an operator reading the file.
func (s *Store) ListBlockedDomains(ctx context.Context) ([]string, error) {
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT domain FROM domains WHERE state IN ('hot', 'cache', 'covered') ORDER BY domain`)
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

// ListRevalidationCandidates returns terminal-state domains (cache / ignore)
// due for a Phase-7 re-probe: their reval_at is null or no newer than dueBefore.
// Manual-deny domains are excluded, mirroring ListProbeCandidates. Ordered
// oldest-checked first (null reval_at first) so the sweep cycles fairly.
func (s *Store) ListRevalidationCandidates(ctx context.Context, limit int, dueBefore time.Time) ([]Domain, error) {
	ts := formatTime(dueBefore)
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT domain, COALESCE(etld_plus_one, ''), COALESCE(first_seen_at, ''),
		       COALESCE(last_seen_at, ''), hit_count, state,
		       COALESCE(cooldown_until, '')
		FROM domains
		WHERE state IN ('cache', 'ignore')
		  AND (reval_at IS NULL OR reval_at <= ?)
		  AND domain NOT IN (SELECT domain FROM manual_entries WHERE list_name = 'deny')
		  AND (etld_plus_one IS NULL OR etld_plus_one = ''
		       OR etld_plus_one NOT IN (SELECT domain FROM manual_entries WHERE list_name = 'deny'))
		ORDER BY reval_at IS NOT NULL, reval_at ASC, last_seen_at DESC
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

// ApplyRevalidation records one Phase-7 re-probe outcome and, when a domain has
// disagreed with its state for `threshold` probes in a row, flips it back to
// 'new' (dropping any cache/hot membership so it leaves the tunnel) for normal
// probing to re-classify. `disagrees` is the caller's judgment that this probe
// contradicts the current state (cache probed Clear, or ignore probed Blocked).
//
// It always stamps reval_at=now. An agreeing probe resets the streak.
//
// Returns an action label ("kept", "pending", "reset", "gone") and the streak
// after this probe.
func (s *Store) ApplyRevalidation(ctx context.Context, domain string, disagrees bool, threshold int, now time.Time) (action string, streak int, err error) {
	if threshold <= 0 {
		threshold = 3
	}
	ts := formatTime(now)
	tx, err := s.wdb.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()

	var state string
	var cur int
	err = tx.QueryRowContext(ctx,
		`SELECT state, reval_streak FROM domains WHERE domain = ?`, domain).Scan(&state, &cur)
	if err == sql.ErrNoRows {
		return "gone", 0, tx.Commit()
	}
	if err != nil {
		return "", 0, err
	}

	if !disagrees {
		if _, err = tx.ExecContext(ctx,
			`UPDATE domains SET reval_at = ?, reval_streak = 0 WHERE domain = ?`, ts, domain); err != nil {
			return "", 0, err
		}
		return "kept", 0, tx.Commit()
	}

	streak = cur + 1
	if streak < threshold {
		if _, err = tx.ExecContext(ctx,
			`UPDATE domains SET reval_at = ?, reval_streak = ? WHERE domain = ?`, ts, streak, domain); err != nil {
			return "", 0, err
		}
		return "pending", streak, tx.Commit()
	}

	// Confirmed disagreement: flip back to 'new' and shed tunnel membership.
	// Normal probing re-classifies from scratch; a still-blocked domain simply
	// re-accumulates to hot/cache, a lifted one settles into ignore.
	if _, err = tx.ExecContext(ctx,
		`UPDATE domains SET state = 'new', reval_streak = 0, reval_at = ?, cooldown_until = NULL WHERE domain = ?`,
		ts, domain); err != nil {
		return "", 0, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM cache_entries WHERE domain = ?`, domain); err != nil {
		return "", 0, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM hot_entries WHERE domain = ?`, domain); err != nil {
		return "", 0, err
	}
	return "reset", 0, tx.Commit()
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

// --- runtime_meta: cross-process heartbeat read/written for doctor & status ---

// MetaRow is one runtime_meta entry: a value and when the daemon last wrote it.
type MetaRow struct {
	Value     string
	UpdatedAt string
}

// SetMeta upserts a key/value into runtime_meta, stamping updated_at = now.
// Cheap enough to call on the daemon's slow heartbeat ticks; goes through the
// single-writer pool like every other write.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.wdb.ExecContext(ctx, `
		INSERT INTO runtime_meta (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value, formatTime(time.Now().UTC()))
	return err
}

// SetMetaTime is SetMeta for a timestamp value, rendered in the storage layout.
func (s *Store) SetMetaTime(ctx context.Context, key string, t time.Time) error {
	return s.SetMeta(ctx, key, formatTime(t))
}

// GetMeta returns one runtime_meta value. ok=false when the key is absent.
func (s *Store) GetMeta(ctx context.Context, key string) (MetaRow, bool, error) {
	var r MetaRow
	err := s.rdb.QueryRowContext(ctx,
		`SELECT value, updated_at FROM runtime_meta WHERE key = ?`, key).Scan(&r.Value, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return MetaRow{}, false, nil
	}
	if err != nil {
		return MetaRow{}, false, err
	}
	return r, true, nil
}

// AllMeta returns the whole runtime_meta table keyed by key.
func (s *Store) AllMeta(ctx context.Context) (map[string]MetaRow, error) {
	rows, err := s.rdb.QueryContext(ctx, `SELECT key, value, updated_at FROM runtime_meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]MetaRow{}
	for rows.Next() {
		var k string
		var r MetaRow
		if err := rows.Scan(&k, &r.Value, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out[k] = r
	}
	return out, rows.Err()
}

// --- aggregate reads for doctor & status ---

// CountDomainsByState returns a state→count map over the domains table.
func (s *Store) CountDomainsByState(ctx context.Context) (map[string]int, error) {
	rows, err := s.rdb.QueryContext(ctx, `SELECT state, COUNT(*) FROM domains GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// CountActiveHot counts hot_entries that have not yet expired (expires_at > now).
func (s *Store) CountActiveHot(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := s.rdb.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM hot_entries WHERE expires_at > ?`, formatTime(now)).Scan(&n)
	return n, err
}

// CountExpiredHot counts hot_entries past their TTL but not yet swept.
func (s *Store) CountExpiredHot(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := s.rdb.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM hot_entries WHERE expires_at <= ?`, formatTime(now)).Scan(&n)
	return n, err
}

// CountCacheRows counts cache_entries.
func (s *Store) CountCacheRows(ctx context.Context) (int, error) {
	var n int
	err := s.rdb.QueryRowContext(ctx, `SELECT COUNT(*) FROM cache_entries`).Scan(&n)
	return n, err
}

// CountOrphanedDomains counts domains in a tunneled tier (hot/cache) with no
// backing hot_entries/cache_entries row — the drift the atomic-transition gap
// can leave behind. Note it deliberately excludes 'ignore': an ignore domain
// has no backing row by design and is not orphaned.
func (s *Store) CountOrphanedDomains(ctx context.Context) (int, error) {
	var n int
	err := s.rdb.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM domains
		WHERE state IN ('hot', 'cache')
		  AND domain NOT IN (SELECT domain FROM hot_entries)
		  AND domain NOT IN (SELECT domain FROM cache_entries)
	`).Scan(&n)
	return n, err
}

// LatestObservationAt returns the most recent domains.last_seen_at — the proxy
// for "when did ladon last see DNS traffic". ok=false on an empty table.
func (s *Store) LatestObservationAt(ctx context.Context) (time.Time, bool, error) {
	return s.maxTime(ctx, `SELECT MAX(last_seen_at) FROM domains`)
}

// LatestProbeAt returns the most recent probes.created_at.
func (s *Store) LatestProbeAt(ctx context.Context) (time.Time, bool, error) {
	return s.maxTime(ctx, `SELECT MAX(created_at) FROM probes`)
}

func (s *Store) maxTime(ctx context.Context, query string) (time.Time, bool, error) {
	var v sql.NullString
	if err := s.rdb.QueryRowContext(ctx, query).Scan(&v); err != nil {
		return time.Time{}, false, err
	}
	if !v.Valid {
		return time.Time{}, false, nil
	}
	return ParseTime(v.String)
}

// RecentProbeStats counts probe rows created since `since`, split into the
// authoritative blocked/clear verdicts. total includes provisional (NULL
// verdict) inline-path rows, so total >= blocked+clear.
func (s *Store) RecentProbeStats(ctx context.Context, since time.Time) (total, blocked, clear int, err error) {
	ts := formatTime(since)
	err = s.rdb.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN verdict = 'clear'   THEN 1 ELSE 0 END), 0)
		FROM probes WHERE created_at >= ?
	`, ts).Scan(&total, &blocked, &clear)
	return total, blocked, clear, err
}

// CountObservationsSince counts domains observed (last_seen_at) at or after
// `since` — a cheap "is fresh DNS flowing" signal for doctor/status.
func (s *Store) CountObservationsSince(ctx context.Context, since time.Time) (int, error) {
	var n int
	err := s.rdb.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM domains WHERE last_seen_at >= ?`, formatTime(since)).Scan(&n)
	return n, err
}

// --- activity & insight reads for `ladon status` ---

// CodeCount is a failure-code tally.
type CodeCount struct {
	Code string
	N    int
}

// TopFailureCodes returns the most common failure codes (the prefix of
// failure_reason before ':') among probes since `since`, largest first.
func (s *Store) TopFailureCodes(ctx context.Context, since time.Time, limit int) ([]CodeCount, error) {
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT CASE WHEN instr(failure_reason, ':') > 0
		            THEN substr(failure_reason, 1, instr(failure_reason, ':') - 1)
		            ELSE failure_reason END AS code,
		       COUNT(*) AS n
		FROM probes
		WHERE created_at >= ? AND failure_reason IS NOT NULL AND failure_reason != ''
		GROUP BY code ORDER BY n DESC, code LIMIT ?
	`, formatTime(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CodeCount
	for rows.Next() {
		var c CodeCount
		if err := rows.Scan(&c.Code, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Decision is a recent entry into the tunnel (hot or cache promotion).
type Decision struct {
	Domain string
	Tier   string // "hot" | "cache"
	At     string
	Reason string
}

// RecentDecisions returns the most recently tunneled domains across both tiers,
// newest first — the "what did ladon just decide to route" feed.
func (s *Store) RecentDecisions(ctx context.Context, limit int) ([]Decision, error) {
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT domain, 'cache' AS tier, promoted_at AS at, COALESCE(reason, '') FROM cache_entries
		UNION ALL
		SELECT domain, 'hot' AS tier, created_at AS at, COALESCE(reason, '') FROM hot_entries
		ORDER BY at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Decision
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.Domain, &d.Tier, &d.At, &d.Reason); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// FamilyCount is an eTLD+1 family with its tunneled-member count.
type FamilyCount struct {
	Family string
	N      int
}

// TopFamilies returns eTLD+1 families with the most tunneled members
// (hot/cache/covered), largest first — where the routed traffic concentrates.
func (s *Store) TopFamilies(ctx context.Context, limit int) ([]FamilyCount, error) {
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT etld_plus_one, COUNT(*) AS n FROM domains
		WHERE state IN ('hot', 'cache', 'covered')
		  AND etld_plus_one IS NOT NULL AND etld_plus_one != ''
		GROUP BY etld_plus_one ORDER BY n DESC, etld_plus_one LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FamilyCount
	for rows.Next() {
		var f FamilyCount
		if err := rows.Scan(&f.Family, &f.N); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// --- single-domain forensics for `ladon why` ---

// GetDomain returns one domains row. ok=false if the domain is unknown.
func (s *Store) GetDomain(ctx context.Context, domain string) (Domain, bool, error) {
	var d Domain
	err := s.rdb.QueryRowContext(ctx, `
		SELECT domain, COALESCE(etld_plus_one, ''), COALESCE(first_seen_at, ''),
		       COALESCE(last_seen_at, ''), hit_count, state, COALESCE(cooldown_until, '')
		FROM domains WHERE domain = ?
	`, domain).Scan(&d.Domain, &d.ETLDPlusOne, &d.FirstSeenAt, &d.LastSeenAt,
		&d.HitCount, &d.State, &d.CooldownUntil)
	if err == sql.ErrNoRows {
		return Domain{}, false, nil
	}
	if err != nil {
		return Domain{}, false, err
	}
	return d, true, nil
}

// ProbeRow is one probes row rendered for forensic display. The OK flags are
// tri-state (NULL = that stage didn't run); verdict is empty for provisional
// inline-path rows.
type ProbeRow struct {
	DNS, TCP, TLS, HTTP sql.NullInt64
	FailureReason       string
	Verdict             string
	CreatedAt           string
}

// Flags renders the four tri-state stage outcomes for display: "ok" (1),
// "x" (0), or "-" (NULL = stage didn't run). Keeps database/sql out of callers.
func (p ProbeRow) Flags() (dns, tcp, tls, http string) {
	return flagStr(p.DNS), flagStr(p.TCP), flagStr(p.TLS), flagStr(p.HTTP)
}

func flagStr(n sql.NullInt64) string {
	if !n.Valid {
		return "-"
	}
	if n.Int64 != 0 {
		return "ok"
	}
	return "x"
}

// RecentProbesForDomain returns the most recent `limit` probe rows for a domain,
// newest first.
func (s *Store) RecentProbesForDomain(ctx context.Context, domain string, limit int) ([]ProbeRow, error) {
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT dns_ok, tcp_ok, tls_ok, http_ok,
		       COALESCE(failure_reason, ''), COALESCE(verdict, ''), created_at
		FROM probes WHERE domain = ?
		ORDER BY created_at DESC, id DESC
		LIMIT ?
	`, domain, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProbeRow
	for rows.Next() {
		var p ProbeRow
		if err := rows.Scan(&p.DNS, &p.TCP, &p.TLS, &p.HTTP,
			&p.FailureReason, &p.Verdict, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// HotEntryFor returns the hot_entries row backing a domain, if any.
func (s *Store) HotEntryFor(ctx context.Context, domain string) (expiresAt, reason string, ok bool, err error) {
	var r sql.NullString
	err = s.rdb.QueryRowContext(ctx,
		`SELECT expires_at, COALESCE(reason, '') FROM hot_entries WHERE domain = ?`, domain).
		Scan(&expiresAt, &r)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return expiresAt, r.String, true, nil
}

// CacheEntryFor returns the cache_entries row backing a domain, if any.
func (s *Store) CacheEntryFor(ctx context.Context, domain string) (promotedAt, reason string, ok bool, err error) {
	var r sql.NullString
	err = s.rdb.QueryRowContext(ctx,
		`SELECT promoted_at, COALESCE(reason, '') FROM cache_entries WHERE domain = ?`, domain).
		Scan(&promotedAt, &r)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return promotedAt, r.String, true, nil
}

// LookupAllIPs returns every IP ever observed for a domain (no freshness
// filter), freshest first — for forensic display, not routing.
func (s *Store) LookupAllIPs(ctx context.Context, domain string) ([]string, error) {
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT ip FROM dns_cache WHERE domain = ? ORDER BY last_seen_at DESC`, domain)
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
