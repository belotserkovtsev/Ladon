// Package dnssrc is the DNS-observation mediator. Each adapter turns one
// resolver's output into a neutral Observation stream; the engine consumes
// Observations without knowing which resolver produced them. Linux gateways
// tail the dnsmasq query log; OPNsense reads records over a unix socket fed by
// the unbound dynlib module.
//
// An Observation is a *resolved* query: a domain plus the IPv4 addresses the
// client actually got. Names that don't resolve to a v4 address (NXDOMAIN,
// AAAA-only, NODATA) are not Observations — they carry nothing to probe or
// tunnel, so each adapter drops them at the source. This is what keeps the
// engine from ever re-resolving a name itself (which on a gateway would re-enter
// the very resolver it observes — a feedback loop).
package dnssrc

import (
	"bufio"
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/belotserkovtsev/ladon/internal/dnsmasq"
	"github.com/belotserkovtsev/ladon/internal/tail"
)

// Observation is one resolved DNS query, resolver-agnostic. Domain is the name
// the client asked for (CNAME chains already re-attributed to it by the
// adapter); IPs are the final IPv4 A-records it resolved to and is always
// non-empty — adapters never emit an unresolved query.
type Observation struct {
	Domain string
	Client string // querying client IP
	IPs    []string
}

// Source yields a neutral Observation stream until ctx is cancelled.
type Source interface {
	Events(ctx context.Context) (<-chan Observation, <-chan error)
}

// Config selects and parameterizes the source.
type Config struct {
	Kind          string // "auto" | "dnsmasq" | "unbound"
	LogPath       string // dnsmasq source: query log to follow
	StartAtEnd    bool   // dnsmasq source: skip existing lines
	UnboundSocket string // unbound source: unix socket to listen on
}

// New picks the source: explicit Kind, or "auto" → unbound on FreeBSD
// (OPNsense), dnsmasq elsewhere.
func New(c Config) Source {
	if Resolve(c.Kind) == "unbound" {
		return &unboundSource{socket: c.UnboundSocket}
	}
	return &dnsmasqSource{logPath: c.LogPath, startAtEnd: c.StartAtEnd}
}

// Resolve expands "auto"/"" to a concrete kind by OS: unbound on FreeBSD
// (OPNsense), dnsmasq elsewhere.
func Resolve(kind string) string {
	if kind == "" || kind == "auto" {
		if runtime.GOOS == "freebsd" {
			return "unbound"
		}
		return "dnsmasq"
	}
	return kind
}

// DefaultUnboundSocket is where the unbound source listens by default. On
// FreeBSD/OPNsense unbound runs chrooted in /var/unbound and its module
// connects to /var/run/ladon-dns.sock from inside that chroot, so the socket
// has to live at /var/unbound/var/run/ladon-dns.sock for the two to meet — no
// operator config needed.
func DefaultUnboundSocket() string {
	if runtime.GOOS == "freebsd" {
		return "/var/unbound/var/run/ladon-dns.sock"
	}
	return "/var/run/ladon-dns.sock"
}

// v4 returns the trimmed string if it is a valid IPv4 literal, else "". The
// engine is v4-only — stun0, the WG subnet, the routing rules and the prod
// ipset are all v4, and v6 answers would only create probe-time "cannot assign"
// failures and pollute dns_cache.
func v4(raw string) string {
	s := strings.TrimSpace(raw)
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
		return s
	}
	return ""
}

// send delivers one Observation, unblocking on ctx so a shutdown can't wedge.
func send(ctx context.Context, out chan<- Observation, obs Observation) bool {
	select {
	case out <- obs:
		return true
	case <-ctx.Done():
		return false
	}
}

// --- unbound mediator: read observations from a unix socket ---
//
// The unbound dynlib module writes one line per resolved query:
//
//	<domain>\t<client-ip>\t<ip1,ip2,...>\n
//
// One line is already a complete, settled observation (the module fires on the
// reply), so each becomes exactly one Observation. Lines with no A-records
// (NXDOMAIN / AAAA-only) are dropped.
type unboundSource struct {
	socket string
}

func (s *unboundSource) Events(ctx context.Context) (<-chan Observation, <-chan error) {
	out := make(chan Observation)
	errs := make(chan error, 1)
	go func() {
		_ = os.Remove(s.socket)
		ln, err := net.Listen("unix", s.socket)
		if err != nil {
			errs <- err
			close(out)
			return
		}
		_ = os.Chmod(s.socket, 0o660)
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		// Close out only after every serveConn sender has returned, or a
		// connection still writing during shutdown would send on a closed channel
		// and panic (dirty exit instead of 0). serveConn unblocks on ctx via send().
		var wg sync.WaitGroup
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					wg.Wait()
					close(out)
					return
				default:
					continue
				}
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				serveConn(ctx, c, out)
			}(conn)
		}
	}()
	return out, errs
}

func serveConn(ctx context.Context, conn net.Conn, out chan<- Observation) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 2 {
			continue
		}
		domain := strings.ToLower(strings.TrimRight(fields[0], "."))
		client := fields[1]
		if domain == "" || client == "" {
			continue
		}
		var ips []string
		if len(fields) >= 3 && fields[2] != "" {
			for _, raw := range strings.Split(fields[2], ",") {
				if ip := v4(raw); ip != "" {
					ips = append(ips, ip)
				}
			}
		}
		if len(ips) == 0 {
			continue // no A-records: nothing to probe or tunnel
		}
		if !send(ctx, out, Observation{Domain: domain, Client: client, IPs: ips}) {
			return
		}
	}
}

// --- dnsmasq mediator: assemble observations from the query log ---
//
// dnsmasq logs a query and its replies as separate lines sharing a query id:
//
//	<id> <client>/1 query[A] foo.com from <client>
//	<id> <client>/1 reply foo.com is 1.2.3.4
//
// CNAME chains reuse the id, and only the terminal A line carries an IP whose
// reply-domain is the LAST hop (a CDN name), not what the client asked for. So
// the adapter buffers by id, keeps the ORIGINAL queried domain, accumulates its
// v4 answers, and emits one settled Observation once the id has been idle for
// `settle` — pushing all of dnsmasq's query/reply framing out of the engine.
type dnsmasqSource struct {
	logPath    string
	startAtEnd bool
	settle     time.Duration // how long an id must be idle before it's emitted
}

func (s *dnsmasqSource) Events(ctx context.Context) (<-chan Observation, <-chan error) {
	lines, errs := tail.Follow(ctx, s.logPath, tail.Options{StartAtEnd: s.startAtEnd})
	out := make(chan Observation)
	settle := s.settle
	if settle <= 0 {
		settle = 150 * time.Millisecond
	}
	go func() {
		defer close(out)

		type pending struct {
			domain string
			client string
			ips    []string
			seen   time.Time
		}
		byID := map[string]*pending{}

		// emit sends a settled query if it actually resolved; unresolved ids
		// (NXDOMAIN / AAAA / NODATA — no v4 answer) are dropped.
		emit := func(p *pending) bool {
			if len(p.ips) == 0 {
				return true
			}
			return send(ctx, out, Observation{Domain: p.domain, Client: p.client, IPs: p.ips})
		}

		ticker := time.NewTicker(settle / 2)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-lines:
				if !ok {
					for _, p := range byID {
						if !emit(p) {
							return
						}
					}
					return
				}
				ev, parsed := dnsmasq.Parse(line)
				if !parsed {
					continue
				}
				switch ev.Action {
				case dnsmasq.Query:
					// v4-only tool: ignore AAAA (and any non-A) queries outright.
					if ev.RecordType != "" && ev.RecordType != "A" {
						continue
					}
					// id reuse means the previous query under it is done — flush it.
					if p, ok := byID[ev.QueryID]; ok {
						if !emit(p) {
							return
						}
					}
					byID[ev.QueryID] = &pending{domain: ev.Domain, client: ev.Peer, seen: time.Now()}
				case dnsmasq.Reply, dnsmasq.Cached:
					ip := v4(ev.Target)
					if ip == "" {
						continue // CNAME / NODATA / v6 line — no address
					}
					p, ok := byID[ev.QueryID]
					if !ok {
						// Reply with no tracked query (log started mid-stream):
						// attribute to the reply domain, best effort.
						p = &pending{domain: ev.Domain, seen: time.Now()}
						byID[ev.QueryID] = p
					}
					p.ips = append(p.ips, ip)
					p.seen = time.Now()
				}
			case t := <-ticker.C:
				for id, p := range byID {
					if t.Sub(p.seen) >= settle {
						if !emit(p) {
							return
						}
						delete(byID, id)
					}
				}
			}
		}
	}()
	return out, errs
}
