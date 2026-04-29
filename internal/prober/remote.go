package prober

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RemoteProber delegates probing to an HTTP service under the operator's
// control. The operator's server is free to probe however it wants (TCP, HTTP,
// cellular, a home Pi behind residential ISP) — it just has to speak the
// small JSON contract documented in docs/probe-api.md.
//
// This lets deployments make reachability decisions from a vantage point
// other than the ladon host itself — useful for exit-compare probing, for
// running probes from an actual DPI'd network, or for federating across
// multiple probe points.
type RemoteProber struct {
	URL        string
	AuthHeader string // header name, e.g. "Authorization" (optional)
	AuthValue  string // header value, e.g. "Bearer xxxxx" (optional)
	Timeout    time.Duration
	HTTP       *http.Client
}

// RemoteRequest is what the remote server receives.
type RemoteRequest struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips,omitempty"`
	Port   int      `json:"port"`
	SNI    string   `json:"sni"`
}

// RemoteResponse is what the remote server returns. Missing fields are
// treated as false / unset — the remote is free to skip stages it can't
// perform (e.g. a cellular prober with no TLS stack can leave tls_ok empty).
//
// FailureCode is optional: older remotes that don't set it are handled by
// parsing the prefix of FailureReason (back-compat — see RemoteProber.Probe).
type RemoteResponse struct {
	DNSOK         bool     `json:"dns_ok"`
	TCPOK         bool     `json:"tcp_ok"`
	TLSOK         bool     `json:"tls_ok"`
	ResolvedIPs   []string `json:"resolved_ips,omitempty"`
	FailureReason string   `json:"reason,omitempty"`
	FailureCode   string   `json:"code,omitempty"`
	LatencyMS     int      `json:"latency_ms,omitempty"`
}

// NewRemote builds a RemoteProber with sensible defaults. A zero timeout
// falls back to 2s — remote probes cross a network and shouldn't use the
// sub-second local default.
func NewRemote(url, authHeader, authValue string, timeout time.Duration) *RemoteProber {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &RemoteProber{
		URL:        url,
		AuthHeader: authHeader,
		AuthValue:  authValue,
		Timeout:    timeout,
		HTTP:       &http.Client{Timeout: timeout},
	}
}

// Name implements Prober.
func (p *RemoteProber) Name() string { return "remote" }

// Probe implements Prober. A transport failure surfaces as
// FailureReason="remote:<err>" and TCP/TLS both false, matching how the local
// prober reports its own transport failures — the engine treats it as Hot,
// which is the safe default when we can't reach our own probe service.
func (p *RemoteProber) Probe(ctx context.Context, domain string, ips []string) Result {
	started := time.Now()
	req := RemoteRequest{
		Domain: domain,
		IPs:    ips,
		Port:   443,
		SNI:    domain,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return failedRemote(domain, ips, "remote:marshal:"+err.Error(), started)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(body))
	if err != nil {
		return failedRemote(domain, ips, "remote:request:"+err.Error(), started)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if p.AuthHeader != "" && p.AuthValue != "" {
		httpReq.Header.Set(p.AuthHeader, p.AuthValue)
	}

	resp, err := p.HTTP.Do(httpReq)
	if err != nil {
		return failedRemote(domain, ips, "remote:"+err.Error(), started)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read a short prefix so the reason stays bounded — operators will see
		// the status code + a hint in logs.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return failedRemote(domain, ips,
			fmt.Sprintf("remote:http_%d:%s", resp.StatusCode, bytes.TrimSpace(snippet)), started)
	}

	var rr RemoteResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return failedRemote(domain, ips, "remote:decode:"+err.Error(), started)
	}

	resolved := rr.ResolvedIPs
	if len(resolved) == 0 {
		resolved = ips
	}
	latency := rr.LatencyMS
	if latency == 0 {
		latency = int(time.Since(started) / time.Millisecond)
	}
	// Back-compat: older remotes don't send `code`; recover it from the
	// reason prefix so engine code can branch on FailureCode uniformly.
	code := FailureCode(rr.FailureCode)
	if code == "" {
		code = parseCode(rr.FailureReason)
	}
	return Result{
		Domain:        domain,
		DNSOK:         rr.DNSOK,
		TCPOK:         rr.TCPOK,
		TLSOK:         rr.TLSOK,
		ResolvedIPs:   resolved,
		FailureCode:   code,
		FailureReason: rr.FailureReason,
		LatencyMS:     latency,
	}
}

func failedRemote(domain string, ips []string, reason string, started time.Time) Result {
	return Result{
		Domain:        domain,
		ResolvedIPs:   ips,
		FailureCode:   CodeRemote,
		FailureReason: reason,
		LatencyMS:     int(time.Since(started) / time.Millisecond),
	}
}

// ErrEmptyURL is returned by config validation when mode=remote is set but no
// URL is provided.
var ErrEmptyURL = errors.New("remote prober: url is required")
