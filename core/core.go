// Package core is ladon's engine as an embeddable library.
//
// The daemon in cmd/ladon is one way to run this engine: it watches a
// resolver's query log and programs kernel sets. A desktop or mobile client is
// another — it already sees DNS, has no kernel sets to program, and enforces by
// handing names to a proxy. Both want the same thing in the middle: observe a
// name, decide whether it is blocked, and stand by that decision only while the
// evidence keeps coming.
//
// That middle is what this package exposes. What it deliberately does not
// expose is how the decision is reached — accumulation windows, family
// inference, revalidation and storage layout stay internal, so they remain free
// to change without breaking anyone embedding the engine.
//
// Usage:
//
//	eng, err := core.New(core.Config{DBPath: "ladon.db"})
//	if err != nil { … }
//	go eng.Run(ctx)
//	eng.OnDNS("example.com", []string{"93.184.216.34"})
//	for v := range eng.Verdicts() {
//	    // v.Domains — what to route through the tunnel, right now
//	}
package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"

	"github.com/belotserkovtsev/ladon/internal/engine"
	"github.com/belotserkovtsev/ladon/internal/prober"
	"github.com/belotserkovtsev/ladon/internal/storage"
)

// Config is what an embedder has to decide. Everything omitted takes the same
// default the daemon uses, so the zero value plus a DBPath is a working engine.
type Config struct {
	// DBPath is where the engine keeps what it has learned. Required: without
	// it every restart starts classifying from nothing, and the accumulation
	// that makes a verdict trustworthy never survives a session.
	DBPath string

	// Enforce, when set, names the kernel sets the engine fills itself —
	// the gateway model. Left empty (the default for a client), the engine
	// decides and publishes without programming anything: enforcement belongs
	// to whoever consumes the verdict.
	Enforce EnforceConfig

	// ProbeTimeout bounds a single probe stage. Zero takes the default.
	ProbeTimeout time.Duration

	// InlineProbeConcurrency, ProbeBatch and ProbeInterval set the pace at
	// which observations become verdicts. Zero takes the client defaults, which
	// are brisker than the daemon's — see Run for why.
	InlineProbeConcurrency int
	ProbeBatch             int
	ProbeInterval          time.Duration

	// Verdicts is how far behind the consumer may fall before updates are
	// dropped rather than buffered. Zero takes a small default.
	VerdictBuffer int

	// Version is recorded so `ladon doctor` and `status` can report what is
	// running when they are pointed at this database.
	Version string

	// DisableDNSVerify turns off the second opinion on refused names. On by
	// default: an embedded engine runs where the resolver can be tampered
	// with, and without the check a whole class of blocks stays invisible.
	DisableDNSVerify bool

	// DNSVerifyURL overrides the encrypted resolver used for that check. Give
	// it by address, not by name, or its own lookup goes through the resolver
	// being checked.
	DNSVerifyURL string

	// DialControl settles each outbound probe socket before it connects, the
	// way net.Dialer.Control does.
	//
	// It exists for embedders that divert this machine's own traffic into a
	// tunnel. A probe that travels through the tunnel measures the tunnel, not
	// the censorship: every diverted name comes back reachable, revalidation
	// clears the diversion, the name breaks, and the cycle repeats. Bind the
	// socket to the physical interface here and the probe stays outside.
	//
	// Left nil, sockets are dialled as they always were.
	DialControl func(network, address string, c syscall.RawConn) error
}

// EnforceConfig names kernel sets for the gateway model. A client leaves it
// zero.
type EnforceConfig struct {
	EngineSet string // set the engine fills from its own verdict
	ManualSet string // set filled from the operator's manual list
	CIDRSet   string // hash:net set for CIDR entries
}

// Verdict is the current answer: the names the engine judges blocked.
//
// It is a whole list rather than a diff because that is what consumers act on —
// a proxy client rewrites its routing table, a set syncer reconciles — and
// because a diff stream forces every consumer to track state it does not want.
type Verdict struct {
	Domains []string

	// IPs are the addresses those names were seen at — what to divert when
	// enforcement works by address rather than by name. Computed exactly as the
	// gateway computes its ipset contents, family expansion included, so a
	// client and a gateway divert the same traffic.
	//
	// A name resolving to several addresses contributes all of them, and a CDN
	// handing out a different address on the next lookup adds that one too:
	// diverting the last answer alone leaves the rest going straight out, which
	// is indistinguishable from not diverting the name at all.
	IPs []string

	At time.Time
}

// Engine is the running classifier.
type Engine struct {
	cfg   Config
	store *storage.Store
	src   *pushSource

	verdicts chan Verdict

	mu      sync.RWMutex
	last    Verdict
	ec      engine.Config // how the engine was started: DesiredIPs computes with the same settings
	running bool
	stopped chan struct{}
}

// New opens the engine's database and prepares it, without starting anything.
// Run does the starting.
func New(cfg Config) (*Engine, error) {
	if cfg.DBPath == "" {
		return nil, errors.New("core: DBPath is required")
	}
	store, err := storage.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("core: open %s: %w", cfg.DBPath, err)
	}
	// Init both creates the schema and runs pending migrations, so an
	// embedder never has to know a database version exists.
	if err := store.Init(context.Background()); err != nil {
		store.Close()
		return nil, fmt.Errorf("core: prepare %s: %w", cfg.DBPath, err)
	}

	buf := cfg.VerdictBuffer
	if buf <= 0 {
		buf = 8
	}
	return &Engine{
		cfg:      cfg,
		store:    store,
		src:      newPushSource(),
		verdicts: make(chan Verdict, buf),
		stopped:  make(chan struct{}),
	}, nil
}

// Run drives the engine until ctx is cancelled. It blocks, mirroring the
// daemon: an embedder runs it in a goroutine.
func (e *Engine) Run(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return errors.New("core: already running")
	}
	e.running = true
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
		close(e.stopped)
	}()

	// No log path: the embedder feeds observations in, so there is nothing to
	// follow on disk.
	ec := engine.Defaults("")
	ec.Version = e.cfg.Version
	if e.cfg.ProbeTimeout > 0 {
		ec.ProbeTimeout = e.cfg.ProbeTimeout
	}
	// The engine observes what it is given, not a file it would have to find.
	ec.Source = e.src

	// Probing keeps a desktop pace, not a gateway's.
	//
	// A gateway watches a handful of clients and can take its time; the queue
	// drains long before anyone notices. A desktop resolves at a different order
	// of magnitude — games, updaters and browsers together produce hundreds of
	// names in minutes — while a person sits in front of it waiting for one
	// particular site to open. At the daemon's pace (4 candidates per 2s tick,
	// probed one after another at up to a timeout each) that queue outruns the
	// prober, and a name observed at the wrong moment waits tens of minutes for
	// a verdict it needed in seconds.
	//
	// So: a wider inline fast path, so a name just resolved is probed while the
	// browser is still opening it, and larger batches on a shorter tick behind
	// it. These stay overridable — an embedder with a different shape of
	// traffic can say so.
	ec.InlineProbeConcurrency = 24
	ec.ProbeBatch = 12
	ec.ProbeInterval = time.Second
	if e.cfg.InlineProbeConcurrency > 0 {
		ec.InlineProbeConcurrency = e.cfg.InlineProbeConcurrency
	}
	if e.cfg.ProbeBatch > 0 {
		ec.ProbeBatch = e.cfg.ProbeBatch
	}
	if e.cfg.ProbeInterval > 0 {
		ec.ProbeInterval = e.cfg.ProbeInterval
	}

	// Nothing is programmed unless the embedder asked for it. The daemon's
	// defaults name kernel sets; a client has none, and the stages that would
	// fill them stand down instead of failing.
	ec.IpsetName = e.cfg.Enforce.EngineSet
	ec.ManualIpsetName = e.cfg.Enforce.ManualSet
	ec.CIDRIpsetName = e.cfg.Enforce.CIDRSet
	ec.ManageDNSMasq = false
	// No gateway here, so no gateway of its own to skip: the peer the
	// daemon ignores by default is a LAN address that never appears.
	ec.IgnorePeer = ""

	// Terminal verdicts get re-examined. On by default here, off for the daemon.
	//
	// A gateway sits in one network for months: what it ruled unblocked stays
	// unblocked, and an operator who wants otherwise says so. A client travels —
	// home wifi, tethered phone, someone else's network — and each one filters
	// differently. Without this, the first network a name is seen on decides it
	// forever: ruled 'ignore' at home, it stays 'ignore' on the mobile network
	// that does block it, and nothing ever revisits the question.
	//
	// The pace is the client's too. Six hours between rounds suits a machine
	// that never moves; a person switching networks needs the stale answers
	// reconsidered within the same sitting.
	ec.Revalidate.Enabled = true
	ec.Revalidate.Interval = 10 * time.Minute
	ec.Revalidate.Batch = 16

	// A client sits where the poisoning happens, so the refusal check is on by
	// default here — unlike the daemon, where reaching outside is the
	// operator's call.
	ec.DNSVerify = engine.DNSVerifyDefaults()
	ec.DNSVerify.Enabled = !e.cfg.DisableDNSVerify
	if e.cfg.DNSVerifyURL != "" {
		ec.DNSVerify.URL = e.cfg.DNSVerifyURL
	}

	// Probes leave through whatever the embedder nominated — set before Run,
	// because from here on several probe goroutines read it.
	if e.cfg.DialControl != nil {
		prober.DialControl = e.cfg.DialControl
	}

	ec.OnVerdict = e.publish

	e.mu.Lock()
	e.ec = ec
	e.mu.Unlock()

	return engine.Run(ctx, e.store, ec)
}

// OnDNS reports one resolved name. It never blocks: an observation that cannot
// be handed over right now is dropped, because the caller is a resolver on the
// answer path and must not wait on the classifier.
//
// Names that resolved to nothing are not observations — there is nothing to
// probe or to route — and are ignored.
func (e *Engine) OnDNS(domain string, ips []string) {
	if domain == "" || len(ips) == 0 {
		return
	}
	e.src.push(domain, ips)
}

// OnDNSDenied reports a name the resolver refused — answered NXDOMAIN, or with
// no address where one was asked for.
//
// Worth reporting even though there is nothing to probe: a resolver on the path
// can answer "no such name" for a name that is perfectly alive, and that block
// is invisible to the probe pipeline because no connection is ever attempted.
// The engine settles such a name by asking again over an encrypted path.
//
// Requires DNSVerify in the engine to be enabled; without it the refusal is
// counted and dropped.
func (e *Engine) OnDNSDenied(domain string) {
	if domain == "" {
		return
	}
	e.src.pushDenied(domain)
}

// Verdicts yields the verdict whenever it changes. The channel is buffered;
// a consumer that stops reading loses updates rather than stalling the engine.
func (e *Engine) Verdicts() <-chan Verdict { return e.verdicts }

// Current returns the verdict as it stands, for a consumer that would rather
// ask than subscribe — a client rebuilding its routing at startup.
func (e *Engine) Current() Verdict {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.last
}

// DesiredIPs asks the engine which addresses to divert, as of right now.
//
// Verdict.IPs is a snapshot taken when the verdict was published; this is the
// live answer. They differ whenever a name already ruled blocked resolves to an
// address it had not resolved to before — routine with a CDN, and exactly the
// moment a diversion is needed, so an embedder that programs addresses should
// ask here rather than reuse the snapshot.
func (e *Engine) DesiredIPs() []string { return e.desiredIPs() }

// desiredIPs asks the engine which addresses to divert. A failure here yields
// no addresses rather than an error: the verdict's names are still worth
// publishing, and the next verdict recomputes anyway.
func (e *Engine) desiredIPs() []string {
	e.mu.RLock()
	ec := e.ec
	e.mu.RUnlock()
	ips, err := engine.DesiredIPs(context.Background(), e.store, ec)
	if err != nil {
		return nil
	}
	return ips
}

// Close releases the database. Cancel Run's context first; Close waits for it
// to unwind so the database is not closed under a running stage.
func (e *Engine) Close() error {
	e.mu.RLock()
	running := e.running
	e.mu.RUnlock()
	if running {
		<-e.stopped
	}
	return e.store.Close()
}

// publish records the new verdict and offers it to the consumer.
func (e *Engine) publish(domains []string) {
	v := Verdict{Domains: domains, IPs: e.desiredIPs(), At: time.Now()}
	e.mu.Lock()
	e.last = v
	e.mu.Unlock()
	select {
	case e.verdicts <- v:
	default: // consumer is behind; the next Current() still tells the truth
	}
}
