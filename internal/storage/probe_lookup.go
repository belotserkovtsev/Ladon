package storage

import (
	"context"
	"database/sql"
	"errors"
)

// GetHotReason returns the reason string from hot_entries for the given
// domain, or "" if no row exists. Multi-protocol classifier uses this to
// mark HOT entries as "sticky against TCP-Ignore override" — if reason
// contains a protocol-specific marker (e.g. "udp-observed"), a later
// TCP+TLS OK verdict should NOT demote the domain, because the HOT was
// driven by evidence the TCP probe can't see.
func (s *Store) GetHotReason(ctx context.Context, domain string) (string, error) {
	var reason sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT reason FROM hot_entries WHERE domain = ?`, domain).Scan(&reason)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return reason.String, nil
}

// LatestProbeOK reports whether the most recent probe row for (domain, proto)
// was successful — both TCPOK and TLSOK (or their protocol-specific
// "transport reachable" / "crypto handshake completed" equivalents) true.
//
// The second return distinguishes "no probe recorded yet" from "probe
// recorded, verdict fail". Callers combining TCP+TLS and QUIC evidence use
// this to know whether enough data exists to make a multi-protocol call,
// versus waiting until both protocols have been probed at least once.
func (s *Store) LatestProbeOK(ctx context.Context, domain, proto string) (ok bool, exists bool, err error) {
	var tcp, tls sql.NullInt64
	err = s.db.QueryRowContext(ctx, `
		SELECT tcp_ok, tls_ok
		FROM probes
		WHERE domain = ? AND proto = ?
		ORDER BY created_at DESC
		LIMIT 1
	`, domain, proto).Scan(&tcp, &tls)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return tcp.Valid && tcp.Int64 == 1 && tls.Valid && tls.Int64 == 1, true, nil
}
