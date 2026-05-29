package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/belotserkovtsev/ladon/internal/migrate"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	return s
}

// TestPragmaAppliedOnEveryConnection is the regression guard for the
// SQLITE_BUSY contention work on ягода 2026-04-18. Two invariants to hold:
//   - every connection of the read pool reports busy_timeout=5000 and
//     foreign_keys=ON (the connector wrapper must apply per-conn PRAGMAs on
//     every fresh conn, not just the first).
//   - the write pool exposes exactly one connection, regardless of how many
//     goroutines call into it — this is how Store guarantees SQLITE_BUSY is
//     structurally impossible instead of merely timeout-dependent.
func TestPragmaAppliedOnEveryConnection(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Read pool: hold 5 conns concurrently so sql.DB is forced to grow the
	// pool past 1. Without holding, the pool reuses a single conn and we'd
	// only ever verify the first PRAGMA application.
	const N = 5
	readConns := make([]*sql.Conn, N)
	for i := range readConns {
		c, err := s.rdb.Conn(ctx)
		if err != nil {
			t.Fatalf("acquire read conn %d: %v", i, err)
		}
		readConns[i] = c
	}
	t.Cleanup(func() {
		for _, c := range readConns {
			c.Close()
		}
	})

	for i, c := range readConns {
		var busyTimeout int
		if err := c.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
			t.Fatalf("read conn %d: query busy_timeout: %v", i, err)
		}
		if busyTimeout != 5000 {
			t.Errorf("read conn %d: busy_timeout=%d, want 5000 — per-conn PRAGMA wrapper regression", i, busyTimeout)
		}
		var foreignKeys int
		if err := c.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
			t.Fatalf("read conn %d: query foreign_keys: %v", i, err)
		}
		if foreignKeys != 1 {
			t.Errorf("read conn %d: foreign_keys=%d, want 1", i, foreignKeys)
		}
	}

	// Write pool: must expose exactly one connection. Acquire one and hold
	// it; a second acquire with a fast-deadline context must time out,
	// proving the cap is enforced. Without the cap, SQLITE_BUSY under burst
	// traffic returns.
	wconn, err := s.wdb.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire write conn: %v", err)
	}
	t.Cleanup(func() { wconn.Close() })

	var writeBusyTimeout, writeForeignKeys int
	if err := wconn.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&writeBusyTimeout); err != nil {
		t.Fatalf("write conn: query busy_timeout: %v", err)
	}
	if writeBusyTimeout != 5000 {
		t.Errorf("write conn: busy_timeout=%d, want 5000", writeBusyTimeout)
	}
	if err := wconn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&writeForeignKeys); err != nil {
		t.Fatalf("write conn: query foreign_keys: %v", err)
	}
	if writeForeignKeys != 1 {
		t.Errorf("write conn: foreign_keys=%d, want 1", writeForeignKeys)
	}

	capCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	second, err := s.wdb.Conn(capCtx)
	if err == nil {
		second.Close()
		t.Error("write pool handed out a second connection while the first was held — SetMaxOpenConns(1) cap broken")
	}

	// journal_mode is database-level (persisted in the header). One check on
	// any pool covers all connections to the file.
	var journalMode string
	if err := s.rdb.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode=%q, want %q", journalMode, "wal")
	}
}

func TestUpsertDomainCreatesAndBumps(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertDomain(ctx, "example.com", "10.10.0.2", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDomain(ctx, "example.com", "10.10.0.2", time.Time{}); err != nil {
		t.Fatal(err)
	}

	doms, err := s.ListRecentDomains(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(doms) != 1 {
		t.Fatalf("want 1 domain, got %d", len(doms))
	}
	if doms[0].HitCount != 2 {
		t.Fatalf("want hit_count=2, got %d", doms[0].HitCount)
	}
	if doms[0].State != "new" {
		t.Fatalf("want state=new, got %s", doms[0].State)
	}
}

func TestInsertProbeAndStampVerdict(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertDomain(ctx, "example.com", "", time.Time{}); err != nil {
		t.Fatal(err)
	}

	ok := true
	id, err := s.InsertProbe(ctx, ProbeResult{
		Domain: "example.com",
		DNSOK:  &ok,
		TCPOK:  &ok,
		TLSOK:  &ok,
	}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatalf("expected non-zero probe id")
	}

	// Fresh probe row is provisional (verdict NULL) — not yet counted.
	if n, err := s.CountBlockedVerdicts(ctx, "example.com", time.Time{}); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Fatalf("want 0 blocked verdicts before stamp, got %d", n)
	}

	if err := s.SetProbeVerdict(ctx, id, "blocked"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CountBlockedVerdicts(ctx, "example.com", time.Time{}); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Fatalf("want 1 blocked verdict after stamp, got %d", n)
	}
}

// TestMigrateSchemaFromLegacyDB seeds a pre-v1.4 schema (retired columns
// present, no verdict, user_version=0), runs the migration list, and asserts the
// dead columns are dropped, probes.verdict is added, existing rows survive,
// user_version is stamped to the baseline, and a second pass is a no-op. Also
// confirms the modernc build supports ALTER TABLE DROP COLUMN inside a tx.
func TestMigrateSchemaFromLegacyDB(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	legacy := `
		CREATE TABLE domains (
			domain TEXT PRIMARY KEY, etld_plus_one TEXT, first_seen_at TEXT,
			last_seen_at TEXT, hit_count INTEGER NOT NULL DEFAULT 0,
			peer_count INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'new',
			score REAL NOT NULL DEFAULT 0, cooldown_until TEXT, last_probe_id INTEGER
		);
		CREATE TABLE probes (
			id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
			dns_ok INTEGER, tcp_ok INTEGER, tls_ok INTEGER, http_ok INTEGER,
			resolved_ips_json TEXT, failure_reason TEXT, latency_ms INTEGER,
			created_at TEXT NOT NULL
		);`
	if _, err := s.wdb.ExecContext(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.wdb.ExecContext(ctx,
		`INSERT INTO domains(domain, state, hit_count) VALUES('keep.test', 'hot', 5)`); err != nil {
		t.Fatal(err)
	}

	if err := migrate.Run(ctx, s.wdb, schema); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cols := func(table string) map[string]bool {
		rows, err := s.wdb.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		m := map[string]bool{}
		for rows.Next() {
			var cid, notnull, pk int
			var name, ctype string
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
				t.Fatal(err)
			}
			m[name] = true
		}
		return m
	}
	d, p := cols("domains"), cols("probes")
	for _, dead := range []string{"score", "peer_count", "last_probe_id"} {
		if d[dead] {
			t.Errorf("domains.%s should have been dropped", dead)
		}
	}
	for _, dead := range []string{"resolved_ips_json", "latency_ms"} {
		if p[dead] {
			t.Errorf("probes.%s should have been dropped", dead)
		}
	}
	if !p["verdict"] {
		t.Error("probes.verdict should have been added")
	}

	var hc int
	if err := s.wdb.QueryRowContext(ctx,
		`SELECT hit_count FROM domains WHERE domain='keep.test'`).Scan(&hc); err != nil {
		t.Fatalf("seed row lost: %v", err)
	}
	if hc != 5 {
		t.Errorf("row not preserved: hit_count=%d, want 5", hc)
	}

	// Baseline stamped so future runs know where the DB sits.
	var ver int
	if err := s.wdb.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if ver != 1 {
		t.Errorf("user_version = %d, want 1", ver)
	}

	// Idempotent: a second pass sees user_version=1 and runs nothing.
	if err := migrate.Run(ctx, s.wdb, schema); err != nil {
		t.Fatalf("second migrate pass: %v", err)
	}
}
