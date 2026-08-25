package dnssrc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

// readObs drains n observations or fails on timeout.
func readObs(t *testing.T, out <-chan Observation, n int) []Observation {
	t.Helper()
	var got []Observation
	deadline := time.After(2 * time.Second)
	for len(got) < n {
		select {
		case o := <-out:
			got = append(got, o)
		case <-deadline:
			t.Fatalf("timed out waiting for %d observations, got %d: %+v", n, len(got), got)
		}
	}
	return got
}

// assertNoMore fails if any observation arrives within d.
func assertNoMore(t *testing.T, out <-chan Observation, d time.Duration) {
	t.Helper()
	select {
	case o := <-out:
		t.Fatalf("unexpected observation: %+v", o)
	case <-time.After(d):
	}
}

func TestUnbound_SettledLineToObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c1, c2 := net.Pipe()
	out := make(chan Observation)
	go serveConn(ctx, c2, out)

	go func() {
		_, _ = c1.Write([]byte("" +
			"a.com\t10.0.0.2\t1.2.3.4,5.6.7.8\n" + // two v4 → one obs, both kept
			"v6.com\t10.0.0.2\t2606:4700::1111\n" + // v6 only → dropped (no v4)
			"nx.com\t10.0.0.2\t\n" + // empty answer (NXDOMAIN) → dropped
			"mix.com\t10.0.0.2\t2606:4700::1111,9.9.9.9\n")) // mixed → only the v4
		_ = c1.Close()
	}()

	got := readObs(t, out, 2)

	if got[0].Domain != "a.com" || got[0].Client != "10.0.0.2" ||
		!reflect.DeepEqual(got[0].IPs, []string{"1.2.3.4", "5.6.7.8"}) {
		t.Fatalf("obs0 = %+v, want a.com/10.0.0.2/[1.2.3.4 5.6.7.8]", got[0])
	}
	if got[1].Domain != "mix.com" || !reflect.DeepEqual(got[1].IPs, []string{"9.9.9.9"}) {
		t.Fatalf("obs1 = %+v, want mix.com/[9.9.9.9] (v6 stripped)", got[1])
	}
	assertNoMore(t, out, 100*time.Millisecond)
}

func TestDnsmasq_AssemblesQueriesAndDropsUnresolved(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "dnsmasq.log")
	// id 1: plain A. id 2: CNAME chain (IP must attribute to the ORIGINAL
	// queried domain, not the CDN hop). id 3: NXDOMAIN (no A reply). id 4:
	// AAAA query (v4-only tool ignores it).
	content := "" +
		"1 10.0.0.2/1 query[A] foo.com from 10.0.0.2\n" +
		"1 10.0.0.2/1 reply foo.com is 1.2.3.4\n" +
		"2 10.0.0.3/1 query[A] bar.com from 10.0.0.3\n" +
		"2 10.0.0.3/1 reply bar.com is <CNAME>\n" +
		"2 10.0.0.3/1 reply cdn.example.net is 9.9.9.9\n" +
		"3 10.0.0.4/1 query[A] missing.lan from 10.0.0.4\n" +
		"4 10.0.0.5/1 query[AAAA] foo.com from 10.0.0.5\n" +
		"4 10.0.0.5/1 reply foo.com is 2606:4700::1\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &dnsmasqSource{logPath: logPath, startAtEnd: false, settle: 20 * time.Millisecond}
	out, _ := src.Events(ctx)

	got := readObs(t, out, 2)
	sort.Slice(got, func(i, j int) bool { return got[i].Domain < got[j].Domain })

	if got[0].Domain != "bar.com" || got[0].Client != "10.0.0.3" ||
		!reflect.DeepEqual(got[0].IPs, []string{"9.9.9.9"}) {
		t.Fatalf("bar obs = %+v, want bar.com/[9.9.9.9] (CNAME re-attributed to original)", got[0])
	}
	if got[1].Domain != "foo.com" || !reflect.DeepEqual(got[1].IPs, []string{"1.2.3.4"}) {
		t.Fatalf("foo obs = %+v, want foo.com/[1.2.3.4]", got[1])
	}
	// missing.lan (NXDOMAIN) and the AAAA foo.com must never surface.
	assertNoMore(t, out, 100*time.Millisecond)
}

func TestDnsmasq_MultiARecordsGroupIntoOneObservation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "dnsmasq.log")
	content := "" +
		"7 10.0.0.2/1 query[A] cdn.com from 10.0.0.2\n" +
		"7 10.0.0.2/1 reply cdn.com is 1.1.1.1\n" +
		"7 10.0.0.2/1 reply cdn.com is 2.2.2.2\n" +
		"7 10.0.0.2/1 reply cdn.com is 3.3.3.3\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &dnsmasqSource{logPath: logPath, startAtEnd: false, settle: 20 * time.Millisecond}
	out, _ := src.Events(ctx)

	got := readObs(t, out, 1)
	if got[0].Domain != "cdn.com" ||
		!reflect.DeepEqual(got[0].IPs, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}) {
		t.Fatalf("obs = %+v, want cdn.com with all three A records in one observation", got[0])
	}
	assertNoMore(t, out, 100*time.Millisecond)
}
