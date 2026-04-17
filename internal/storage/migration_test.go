package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// TestMigrateProbesProto_AddsColumnToExistingDB simulates a pre-v1.0 database
// (probes table without proto column) and verifies Init() back-fills the
// column with default 'tcp+tls' without losing existing rows.
func TestMigrateProbesProto_AddsColumnToExistingDB(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "engine.db")

	// Bootstrap the v0.x schema manually (probes table without proto column)
	// to emulate an upgrade path.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	oldSchema := `
		CREATE TABLE probes (
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
		);`
	if _, err := db.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	// Insert a pre-migration row so we can verify backfill value.
	if _, err := db.Exec(
		`INSERT INTO probes (domain, dns_ok, created_at) VALUES (?, 1, '2026-04-17 10:00:00')`,
		"example.com"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Open via the ladon Store — Init() should detect missing column and add it.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("Init migration failed: %v", err)
	}

	// Column should now exist and pre-existing row should carry 'tcp+tls'.
	var proto string
	if err := s.db.QueryRowContext(ctx,
		`SELECT proto FROM probes WHERE domain = ?`, "example.com").Scan(&proto); err != nil {
		t.Fatalf("query proto: %v", err)
	}
	if proto != "tcp+tls" {
		t.Errorf("proto = %q, want 'tcp+tls' default backfill", proto)
	}

	// Running Init again must be a no-op (idempotent).
	if err := s.Init(ctx); err != nil {
		t.Fatalf("second Init should be no-op, got: %v", err)
	}
}

// TestInit_CreatesObservedFlowsTable is a fresh-install sanity check: after
// Init() on an empty DB, observed_flows exists with the expected shape and
// is writable.
func TestInit_CreatesObservedFlowsTable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO observed_flows (dst_ip, proto, dst_port, src_client, observed_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"162.159.138.232", "tcp", 443, "192.168.0.53", "2026-04-17 17:00:00")
	if err != nil {
		t.Fatalf("insert observed_flows row: %v", err)
	}

	var cnt int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM observed_flows WHERE dst_ip = ?`,
		"162.159.138.232").Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Errorf("observed_flows count = %d, want 1", cnt)
	}
}

// TestInit_FreshDBHasProtoColumn confirms that a brand-new DB created via
// Init() has proto column (from schema.sql), not relying on migration.
func TestInit_FreshDBHasProtoColumn(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info('probes') WHERE name = 'proto'`).
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("proto column missing on fresh schema — want present")
	}
}
