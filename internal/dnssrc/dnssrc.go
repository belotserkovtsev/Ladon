// Package dnssrc is the DNS-observation mediator. Each adapter turns one
// resolver's output into a neutral Record stream; the engine consumes Records
// without knowing which resolver produced them. Linux gateways tail the dnsmasq
// query log; OPNsense reads records over a unix socket fed by the unbound
// python module.
package dnssrc

import (
	"bufio"
	"context"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/belotserkovtsev/ladon/internal/dnsmasq"
	"github.com/belotserkovtsev/ladon/internal/tail"
)

// Kind distinguishes a client query from a resolved reply.
type Kind int

const (
	Query Kind = iota // a client asked for Domain
	Reply             // Domain resolved to IP
)

// Record is the neutral DNS observation every mediator emits. It is the common
// protocol between mediators (dnsmasq, unbound, …) and the engine.
type Record struct {
	Kind    Kind
	Domain  string // lowercased, trailing dot stripped
	Client  string // querying client IP (Query records)
	IP      string // resolved IPv4 (Reply records)
	ChainID string // correlates Query↔Reply for CNAME re-attribution
}

// Source yields a neutral Record stream until ctx is cancelled.
type Source interface {
	Events(ctx context.Context) (<-chan Record, <-chan error)
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

// --- dnsmasq mediator: tail the query log, map each line to a Record ---

type dnsmasqSource struct {
	logPath    string
	startAtEnd bool
}

func (s *dnsmasqSource) Events(ctx context.Context) (<-chan Record, <-chan error) {
	lines, errs := tail.Follow(ctx, s.logPath, tail.Options{StartAtEnd: s.startAtEnd})
	out := make(chan Record)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-lines:
				if !ok {
					return
				}
				ev, parsed := dnsmasq.Parse(line)
				if !parsed {
					continue
				}
				if rec, ok := fromDnsmasq(ev); ok {
					if !send(ctx, out, rec) {
						return
					}
				}
			}
		}
	}()
	return out, errs
}

// fromDnsmasq maps a dnsmasq event to a neutral Record. Only query/reply lines
// carry observations; forwarded/cached/config are dropped.
func fromDnsmasq(ev *dnsmasq.Event) (Record, bool) {
	switch ev.Action {
	case dnsmasq.Query:
		return Record{Kind: Query, Domain: ev.Domain, Client: ev.Peer, ChainID: ev.QueryID}, true
	case dnsmasq.Reply:
		return Record{Kind: Reply, Domain: ev.Domain, IP: ev.Target, ChainID: ev.QueryID}, true
	}
	return Record{}, false
}

// --- unbound mediator: read observations from a unix socket ---
//
// The unbound python module writes one line per resolved query:
//
//	<domain>\t<client-ip>\t<ip1,ip2,...>\n
//
// Each becomes a Query record (drives discovery + inline probe) plus one Reply
// record per A address (feeds dns_cache).
type unboundSource struct {
	socket string
}

func (s *unboundSource) Events(ctx context.Context) (<-chan Record, <-chan error) {
	out := make(chan Record)
	errs := make(chan error, 1)
	go func() {
		defer close(out)
		_ = os.Remove(s.socket)
		ln, err := net.Listen("unix", s.socket)
		if err != nil {
			errs <- err
			return
		}
		_ = os.Chmod(s.socket, 0o660)
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			go serveConn(ctx, conn, out)
		}
	}()
	return out, errs
}

func serveConn(ctx context.Context, conn net.Conn, out chan<- Record) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	var seq int
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
			ips = strings.Split(fields[2], ",")
		}
		seq++
		id := strconv.Itoa(seq)
		if !send(ctx, out, Record{Kind: Query, Domain: domain, Client: client, ChainID: id}) {
			return
		}
		for _, ip := range ips {
			if !send(ctx, out, Record{Kind: Reply, Domain: domain, IP: strings.TrimSpace(ip), ChainID: id}) {
				return
			}
		}
	}
}

func send(ctx context.Context, out chan<- Record, rec Record) bool {
	select {
	case out <- rec:
		return true
	case <-ctx.Done():
		return false
	}
}
