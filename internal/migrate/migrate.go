// Package migrate is a tiny, dependency-free schema-migration runner for the
// SQLite database ladon owns. It records the applied schema version in the
// database's own PRAGMA user_version and applies, lowest version first and
// exactly once, every migration newer than the database. Each migration runs
// inside its own transaction; on success the runner stamps the new user_version
// in that same transaction, so a crash can never leave a database
// half-migrated-but-marked-done.
//
// Extending the schema is append-only: add a Migration with the next version
// number to the ordered list the caller passes to Run. Never edit or renumber a
// migration that has shipped — a database already past it will not re-run it.
package migrate

import (
	"context"
	"database/sql"
	"fmt"
)

// Migration is one ordered, run-once schema step. Up runs inside a transaction
// that the runner commits (stamping user_version) or rolls back as a unit, so
// a failed Up leaves the database exactly as it was before the step.
type Migration struct {
	Version int    // strictly increasing, starts at 1 (0 means "fresh, nothing applied")
	Name    string // human label, surfaced in error messages
	Up      func(ctx context.Context, tx *sql.Tx) error
}

// SQL bundles one or more statements into an Up func, executed in order.
func SQL(stmts ...string) func(context.Context, *sql.Tx) error {
	return func(ctx context.Context, tx *sql.Tx) error {
		for _, s := range stmts {
			if _, err := tx.ExecContext(ctx, s); err != nil {
				return err
			}
		}
		return nil
	}
}

// Run applies every migration in ms whose Version exceeds the database's current
// user_version, lowest version first, each in its own transaction. It is
// idempotent: a database already at or beyond the highest version is left
// untouched. ms must be ordered by strictly increasing Version; Run validates
// this so a misnumbered list fails loudly instead of silently skipping a step.
func Run(ctx context.Context, db *sql.DB, ms []Migration) error {
	var current int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("migrate: read user_version: %w", err)
	}

	prev := 0
	for _, m := range ms {
		if m.Version <= prev {
			return fmt.Errorf("migrate: versions must strictly increase, got %d after %d (%q)", m.Version, prev, m.Name)
		}
		prev = m.Version

		if m.Version <= current {
			continue
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("migrate: begin v%d (%q): %w", m.Version, m.Name, err)
		}
		if err := m.Up(ctx, tx); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate: apply v%d (%q): %w", m.Version, m.Name, err)
		}
		// PRAGMA user_version takes a literal, not a bound parameter; m.Version
		// is an int we control, so the formatted value is safe. The write lands
		// in the DB header inside this tx, so it commits/rolls back atomically
		// with the migration body.
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, m.Version)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate: stamp v%d (%q): %w", m.Version, m.Name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate: commit v%d (%q): %w", m.Version, m.Name, err)
		}
	}
	return nil
}
