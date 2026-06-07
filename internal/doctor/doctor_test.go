package doctor

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

func TestBuildVerdict(t *testing.T) {
	r := build("v1", []Check{{Stage: StageEngine, Status: StatusOK}})
	if r.Verdict != StatusOK || r.Exit != 0 {
		t.Fatalf("ok: verdict=%v exit=%d", r.Verdict, r.Exit)
	}
	r = build("v1", []Check{{Stage: StageEngine, Status: StatusOK}, {Stage: StageAccum, Status: StatusWarn}})
	if r.Verdict != StatusWarn || r.Exit != 1 {
		t.Fatalf("warn: verdict=%v exit=%d", r.Verdict, r.Exit)
	}
	r = build("v1", []Check{{Stage: StageAccum, Status: StatusWarn}, {Stage: StageEnforce, Status: StatusFail}})
	if r.Verdict != StatusFail || r.Exit != 2 {
		t.Fatalf("fail dominates warn: verdict=%v exit=%d", r.Verdict, r.Exit)
	}
}

func TestFirstBrokenEarliestStage(t *testing.T) {
	r := build("v1", []Check{
		{Stage: StageEnforce, Status: StatusFail, Title: "ipset пуст"},
		{Stage: StageInput, Status: StatusFail, Title: "нет DNS"},
	})
	fb := r.firstBroken()
	if fb == nil || fb.Stage != StageInput {
		t.Fatalf("firstBroken should pick the earliest stage (Input), got %+v", fb)
	}
}

func TestRenderHealthyFooter(t *testing.T) {
	var buf bytes.Buffer
	build("v1.4.0", []Check{{Stage: StageEngine, Status: StatusOK, Title: "живой"}}).Render(&buf)
	out := buf.String()
	if !strings.Contains(out, "🟢 ЗДОРОВ") {
		t.Errorf("missing healthy headline: %q", out)
	}
	if !strings.Contains(out, "НИЖЕ ладона") {
		t.Errorf("healthy report should point downstream: %q", out)
	}
}

func TestRenderBrokenHeadlineAndFix(t *testing.T) {
	var buf bytes.Buffer
	build("v1", []Check{
		{Stage: StageEnforce, Status: StatusFail, Title: "ladon_engine ПУСТОЙ",
			Detail: "в наборе 0", Fix: "systemctl restart ladon"},
	}).Render(&buf)
	out := buf.String()
	if !strings.Contains(out, "🔴 СЛОМАН") {
		t.Errorf("missing broken headline: %q", out)
	}
	if !strings.Contains(out, "ПЕРВОЕ ПОРВАННОЕ ЗВЕНО") {
		t.Errorf("missing first-broken-link line: %q", out)
	}
	if !strings.Contains(out, "fix: systemctl restart ladon") {
		t.Errorf("fix should render for a failing check: %q", out)
	}
}

// Run against an empty DB (no environment probing) should diagnose the input
// stage: ladon sees no DNS, so the whole chain is broken there.
func TestRunEmptyDBFailsAtInput(t *testing.T) {
	st, err := storage.Open(filepath.Join(t.TempDir(), "doctor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Init(ctx); err != nil {
		t.Fatal(err)
	}

	rep := Run(ctx, st, Params{
		Version:        "test",
		ExpiryInterval: 30 * time.Second,
		Now:            time.Now().UTC(),
		ProbeService:   false,
		ProbeIpset:     false,
	})
	if rep.Verdict != StatusFail {
		t.Fatalf("empty DB should be broken, got verdict=%v exit=%d", rep.Verdict, rep.Exit)
	}
	fb := rep.firstBroken()
	if fb == nil || fb.Stage != StageInput {
		t.Fatalf("expected input-stage failure, got %+v", fb)
	}
}

// With fresh observations and a recent heartbeat (env probing off), the
// internal stages should all be green.
func TestRunHealthyWhenFresh(t *testing.T) {
	st, err := storage.Open(filepath.Join(t.TempDir(), "doctor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Init(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	if err := st.UpsertDomain(ctx, "seen.example", now); err != nil {
		t.Fatal(err)
	}
	// A recent probe so the decision stage looks live (not "пробы отстают"),
	// and the domain leaves the pending 'new' set.
	bp := func(v bool) *bool { return &v }
	if _, err := st.InsertProbe(ctx, storage.ProbeResult{
		Domain: "seen.example", DNSOK: bp(true), TCPOK: bp(true), TLSOK: bp(true),
	}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDomainState(ctx, "seen.example", "ignore", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMetaTime(ctx, "last_tick_at", now); err != nil {
		t.Fatal(err)
	}

	rep := Run(ctx, st, Params{
		Version:        "test",
		ExpiryInterval: 30 * time.Second,
		Now:            now,
		ProbeService:   false,
		ProbeIpset:     false,
	})
	if rep.Verdict != StatusOK {
		var bad []string
		for _, c := range rep.Checks {
			if c.Status != StatusOK {
				bad = append(bad, c.Stage+"/"+c.Title)
			}
		}
		t.Fatalf("expected healthy, got verdict=%v non-ok=%v", rep.Verdict, bad)
	}
}
