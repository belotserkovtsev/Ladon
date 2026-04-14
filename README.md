# split-engine

Smart split engine for EN1GMA.

## Goal

Automatically discover domains that should go through split routing, unlock them quickly when they appear blocked, and gradually promote stable candidates into a persistent cache.

## Core pipeline

1. **Watcher**
   - consumes DNS events from dnsmasq
   - extracts candidate domains
   - enqueues unseen domains for probing

2. **Prober**
   - resolves A/AAAA
   - runs TCP 443 probe
   - runs TLS SNI probe when needed
   - stores raw probe outcomes

3. **Decision engine**
   - decides whether to ignore, watch, or hot-unlock
   - adds temporary hot entries with TTL

4. **Scorer**
   - accumulates evidence over time
   - promotes stable domains from hot candidates into persistent cache

5. **IP set builder**
   - builds final runtime set from:
     - cache
     - hot
     - manual
   - applies updates atomically

## Repository layout

- `cmd/split-engine/` — CLI entry point
- `internal/storage/` — SQLite access layer + embedded schema
- `internal/watcher/` — DNS event ingest
- `internal/prober/` — staged DNS/TCP/TLS probes
- `internal/decision/` — probe → verdict (stub)
- `internal/scorer/` — evidence accumulation and promotion (stub)
- `docs/` — architecture and design notes
- `domains/` — manual and curated domain sources
- `state/` — local state files for development only (SQLite DB, gitignored)

## Build & run

Requires Go 1.23+.

```sh
go build ./cmd/split-engine
./split-engine init-db
./split-engine probe example.com
./split-engine observe some.domain.dev 10.10.0.2
./split-engine list
go test ./...
```

## States

A domain can move through these states:

- `new`
- `watch`
- `hot`
- `cache`
- `manual`
- `deny`

## Current scope

This repo is currently for engine development only.
Integration with gateway/runtime ipset updates will be added later.
