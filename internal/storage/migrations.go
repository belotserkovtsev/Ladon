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
	{
		Version: 2,
		Name:    "index probes(domain, created_at) for the scorer's per-domain count",
		// The scorer runs CountBlockedVerdicts (WHERE domain=? AND created_at>=?
		// AND verdict='blocked') once per hot domain every interval; probes grows
		// unbounded until an operator prunes, so this keeps that count off a full
		// table scan. Lives here, not in schema.sql, so fresh and upgraded DBs
		// both get it through the same path.
		Up: migrate.SQL(
			`CREATE INDEX IF NOT EXISTS idx_probes_domain_created ON probes(domain, created_at)`,
		),
	},
	{
		Version: 3,
		Name:    "index domains(etld_plus_one, state) for the family-confirmation count",
		// FamilyConfirmed counts hot/cache members per eTLD+1 on every ingest;
		// this keeps that count off a full domains scan.
		Up: migrate.SQL(
			`CREATE INDEX IF NOT EXISTS idx_domains_etld_state ON domains(etld_plus_one, state)`,
		),
	},
	{
		Version: 4,
		Name:    "runtime_meta key/value heartbeat for cross-process status (doctor/status)",
		// The daemon writes liveness + last-reconcile facts here; the separate
		// `ladon doctor`/`status` processes read them (they can't see the
		// daemon's memory). Values that ARE derivable from existing tables
		// (last observation, last probe) are NOT stored here — only facts the
		// schema otherwise loses (reconcile timestamps/counts, scorer runs,
		// process identity).
		Up: migrate.SQL(
			`CREATE TABLE IF NOT EXISTS runtime_meta (
				key        TEXT PRIMARY KEY,
				value      TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
		),
	},
	{
		Version: 5,
		Name:    "domains.reval_at + reval_streak for Phase-7 terminal-state revalidation",
		// The revalidator re-probes terminal-state domains (cache/ignore) on a
		// slow cadence and flips one back to 'new' once `streak` consecutive
		// probes disagree with its state, so a lifted block (or a domain blocked
		// only later) stops being permanent. reval_at rate-limits per domain;
		// reval_streak is the disagreement counter. Existing rows read NULL / 0.
		Up: migrate.SQL(
			`ALTER TABLE domains ADD COLUMN reval_at TEXT`,
			`ALTER TABLE domains ADD COLUMN reval_streak INTEGER NOT NULL DEFAULT 0`,
		),
	},
	// v6+ — append clean, version-numbered steps here.
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
