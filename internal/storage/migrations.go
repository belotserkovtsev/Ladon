package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/belotserkovtsev/ladon/internal/migrate"
)

// schema is the ordered migration list for ladon's engine database. migrate.Run
// applies any entry newer than the database's user_version, lowest first, each
// in its own transaction.
//
// EXTENDING: to change the schema in a future release, append an entry with the
// next version number. NEVER edit or renumber a migration that has shipped — a
// database already past it will not re-run it. New columns, tables, indexes, and
// data backfills go in a NEW migration; schema.sql is frozen as the v1 baseline.
var schema = []migrate.Migration{
	{
		Version: 1,
		Name:    "baseline schema + retire pre-v1.4 columns",
		Up: func(ctx context.Context, tx *sql.Tx) error {
			// Fresh installs get the whole layout here (every CREATE is IF NOT
			// EXISTS). Databases that predate user_version read 0 and run this
			// too: the CREATEs no-op on their existing tables, and
			// reconcileLegacy converges any older column set to the baseline
			// (adds probes.verdict, drops the retired columns). Either way the
			// database ends at the v1 shape and is stamped user_version=1.
			if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
				return err
			}
			return reconcileLegacy(ctx, tx)
		},
	},
	// v2+ — append clean, version-numbered steps here, e.g.:
	// {
	// 	Version: 2,
	// 	Name:    "index probes(domain, created_at) for the scorer count",
	// 	Up: migrate.SQL(
	// 		`CREATE INDEX IF NOT EXISTS idx_probes_domain_created ON probes(domain, created_at)`,
	// 	),
	// },
}

// reconcileLegacy converges an un-versioned (pre-user_version) database to the
// v1 baseline column layout. It is feature-detected and idempotent precisely
// because such databases predate migration tracking and may sit at any older
// schema; from v2 on, migrations assume the known v1 baseline and need no such
// probing. A fresh database created from schema.sql hits this as a guarded
// no-op.
func reconcileLegacy(ctx context.Context, tx *sql.Tx) error {
	// Table names below are compile-time constants ("probes"/"domains"). PRAGMA
	// and ALTER TABLE do not accept a bound parameter for the table/column name,
	// so they are interpolated — never route a caller-supplied name through here.
	has := func(table, col string) (bool, error) {
		rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var cid, notnull, pk int
			var name, ctype string
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
				return false, err
			}
			if name == col {
				return true, nil
			}
		}
		return false, rows.Err()
	}

	// Required: the scorer counts blocked verdicts off this column.
	if ok, err := has("probes", "verdict"); err != nil {
		return err
	} else if !ok {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE probes ADD COLUMN verdict TEXT`); err != nil {
			return fmt.Errorf("add probes.verdict: %w", err)
		}
	}

	// Retire columns no longer read by any code path (KISS — minimal data).
	for _, d := range []struct{ table, col string }{
		{"domains", "score"},
		{"domains", "peer_count"},
		{"domains", "last_probe_id"},
		{"probes", "resolved_ips_json"},
		{"probes", "latency_ms"},
	} {
		ok, err := has(d.table, d.col)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+d.table+` DROP COLUMN `+d.col); err != nil {
			return fmt.Errorf("drop %s.%s: %w", d.table, d.col, err)
		}
	}
	return nil
}
