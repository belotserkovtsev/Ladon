package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRunAppliesInOrderAndStamps(t *testing.T) {
	db := openDB(t)
	var order []int
	ms := []Migration{
		{Version: 1, Name: "one", Up: func(ctx context.Context, tx *sql.Tx) error {
			order = append(order, 1)
			_, err := tx.ExecContext(ctx, `CREATE TABLE a(x)`)
			return err
		}},
		{Version: 2, Name: "two", Up: func(ctx context.Context, tx *sql.Tx) error {
			order = append(order, 2)
			_, err := tx.ExecContext(ctx, `CREATE TABLE b(x)`)
			return err
		}},
	}
	if err := Run(context.Background(), db, ms); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := userVersion(t, db); got != 2 {
		t.Errorf("user_version = %d, want 2", got)
	}
	if len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Errorf("apply order = %v, want [1 2]", order)
	}
}

func TestRunIsIdempotentAndSkipsApplied(t *testing.T) {
	db := openDB(t)
	v1Runs := 0
	ms := []Migration{
		{Version: 1, Name: "one", Up: func(ctx context.Context, tx *sql.Tx) error { v1Runs++; return nil }},
	}
	for i := 0; i < 3; i++ {
		if err := Run(context.Background(), db, ms); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if v1Runs != 1 {
		t.Errorf("v1 applied %d times, want 1", v1Runs)
	}

	// Appending a newer migration runs only the new one, not the applied prefix.
	v2Runs := 0
	ms = append(ms, Migration{Version: 2, Name: "two", Up: func(ctx context.Context, tx *sql.Tx) error { v2Runs++; return nil }})
	if err := Run(context.Background(), db, ms); err != nil {
		t.Fatalf("run after append: %v", err)
	}
	if v1Runs != 1 || v2Runs != 1 {
		t.Errorf("after append: v1Runs=%d v2Runs=%d, want 1 and 1", v1Runs, v2Runs)
	}
	if got := userVersion(t, db); got != 2 {
		t.Errorf("user_version = %d, want 2", got)
	}
}

func TestRunRollsBackOnError(t *testing.T) {
	db := openDB(t)
	ms := []Migration{
		{Version: 1, Name: "creates then fails", Up: func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `CREATE TABLE a(x)`); err != nil {
				return err
			}
			return fmt.Errorf("boom")
		}},
	}
	if err := Run(context.Background(), db, ms); err == nil {
		t.Fatal("expected error from failing migration")
	}
	// The version must not advance and the table created before the failure must
	// be rolled back with the rest of the transaction.
	if got := userVersion(t, db); got != 0 {
		t.Errorf("user_version = %d, want 0 (rolled back)", got)
	}
	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='a'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("table 'a' still exists; migration body was not rolled back")
	}
}

func TestRunRejectsNonIncreasingVersions(t *testing.T) {
	db := openDB(t)
	ms := []Migration{
		{Version: 1, Name: "one", Up: func(ctx context.Context, tx *sql.Tx) error { return nil }},
		{Version: 1, Name: "dup", Up: func(ctx context.Context, tx *sql.Tx) error { return nil }},
	}
	if err := Run(context.Background(), db, ms); err == nil {
		t.Fatal("expected error for non-increasing versions")
	}
}
