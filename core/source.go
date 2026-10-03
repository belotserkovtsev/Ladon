package core

import (
	"context"

	"github.com/belotserkovtsev/ladon/internal/dnssrc"
)

// pushSource turns OnDNS calls into the observation stream the engine consumes.
//
// The built-in sources pull — they follow a query log or read a socket. An
// embedder pushes: it already has the name and the addresses, because it
// answered the query itself. This adapter is the join between the two, and it
// is the whole reason the engine can be embedded without a resolver log to
// point it at.
type pushSource struct {
	ch chan dnssrc.Observation
}

func newPushSource() *pushSource {
	// Buffered because the producer is on a resolver's answer path: a DNS reply
	// must not wait for the classifier to catch up. When the buffer fills, the
	// observation is dropped — the same name will be looked up again shortly,
	// and a dropped one costs a later verdict, while a blocked reply costs the
	// user their page.
	return &pushSource{ch: make(chan dnssrc.Observation, 256)}
}

// localPeer is who the engine records as having asked.
//
// On a gateway the peer distinguishes the machines behind it, and an
// observation with no peer is malformed — ingest drops it. Embedded there is
// only ever one asker, the host itself, so the field is filled rather than left
// empty: without it every observation looks malformed and the engine ingests
// nothing at all.
const localPeer = "127.0.0.1"

func (p *pushSource) push(domain string, ips []string) {
	select {
	case p.ch <- dnssrc.Observation{Domain: domain, Client: localPeer, IPs: ips}:
	default:
	}
}

// Events implements dnssrc.Source.
//
// The error channel stays open and silent for the engine's whole life: a
// pushed source has no file to lose and no socket to drop, so there is no
// failure for it to report. It is created because the interface promises one,
// and closing it early would read as the source giving up.
func (p *pushSource) Events(ctx context.Context) (<-chan dnssrc.Observation, <-chan error) {
	out := make(chan dnssrc.Observation)
	errs := make(chan error)
	go func() {
		defer close(out)
		defer close(errs)
		for {
			select {
			case <-ctx.Done():
				return
			case obs := <-p.ch:
				select {
				case out <- obs:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, errs
}

// pushDenied reports a refused name. IPs stay empty — that is what makes it a
// refusal rather than an observation.
func (p *pushSource) pushDenied(domain string) {
	select {
	case p.ch <- dnssrc.Observation{Domain: domain, Client: localPeer, Denied: true}:
	default:
	}
}
