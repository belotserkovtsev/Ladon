// Package doctor implements `ladon doctor`: a one-shot health check that walks
// ladon's own pipeline (engine → input → decision → accumulation → ipset
// output) and reports, in plain language, the first place the chain breaks.
//
// Scope is deliberately INTERNAL to ladon. The doctor never inspects the
// tunnel, iptables, ip-rule, or the exit node — ladon only fills ipsets and
// stays routing-agnostic, so the doctor does too. The payoff is that an
// all-green report is a clean "ladon is healthy — if sites still break, the
// cause is downstream (tunnel / exit / DPI), which is outside ladon's job."
package doctor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"time"

	"github.com/belotserkovtsev/ladon/internal/ipset"
	"github.com/belotserkovtsev/ladon/internal/storage"
	"github.com/belotserkovtsev/ladon/internal/ui"
)

// Status is a single check's outcome.
type Status int

const (
	StatusOK Status = iota
	StatusWarn
	StatusFail
)

// Pipeline stages, listed in the order traffic flows through them. The "first
// broken link" headline picks the earliest stage holding a failing check.
const (
	StageEngine  = "Движок"
	StageInput   = "Вход (DNS)"
	StageDecide  = "Решение"
	StageAccum   = "Накопление"
	StageEnforce = "Выход (ipset)"
)

var stageOrder = []string{StageEngine, StageInput, StageDecide, StageAccum, StageEnforce}

// Check is one diagnostic line.
type Check struct {
	Stage  string
	Status Status
	Title  string // short human label ("служба активна")
	Detail string // optional one-line elaboration
	Fix    string // optional suggested command/action when not OK
}

// Report is the full result: every check plus the rolled-up verdict.
type Report struct {
	Version string
	Checks  []Check
	Verdict Status // worst status across all checks
	Exit    int    // 0 healthy, 1 degraded, 2 broken
}

// Params carries the bits of engine config the checks need, plus injection
// points for tests (Now, and the env-probe toggles).
type Params struct {
	Version         string
	IpsetEngineName string
	IpsetManualName string
	IpsetCIDRName   string
	ExpiryInterval  time.Duration // engine liveness cadence — sets the staleness bar
	ServiceName     string        // systemd unit, e.g. "ladon"

	// Now is the clock reference; zero means time.Now().UTC().
	Now time.Time
	// ProbeService / ProbeIpset gate the shell-outs (off in unit tests).
	ProbeService bool
	ProbeIpset   bool
}

func (p Params) now() time.Time {
	if p.Now.IsZero() {
		return time.Now().UTC()
	}
	return p.Now.UTC()
}

// Run performs all checks and returns a Report. It never returns an error —
// every failure mode (DB error, missing tool, dead set) becomes a check so the
// operator sees one consistent surface.
func Run(ctx context.Context, store *storage.Store, p Params) Report {
	now := p.now()
	var checks []Check
	add := func(c Check) { checks = append(checks, c) }

	checks = append(checks, engineChecks(ctx, store, p, now)...)
	checks = append(checks, inputChecks(ctx, store, now)...)
	checks = append(checks, decideChecks(ctx, store, now)...)
	checks = append(checks, accumChecks(ctx, store, now)...)
	checks = append(checks, enforceChecks(ctx, store, p, now)...)
	_ = add

	return build(p.Version, checks)
}

// build rolls a check slice into a Report: verdict = worst status, exit code
// 0/1/2. Pure — the unit tests drive it directly.
func build(version string, checks []Check) Report {
	verdict := StatusOK
	for _, c := range checks {
		if c.Status > verdict {
			verdict = c.Status
		}
	}
	exit := 0
	switch verdict {
	case StatusWarn:
		exit = 1
	case StatusFail:
		exit = 2
	}
	return Report{Version: version, Checks: checks, Verdict: verdict, Exit: exit}
}

// firstBroken returns the earliest-stage failing check, or nil if none failed.
func (r Report) firstBroken() *Check {
	rank := map[string]int{}
	for i, s := range stageOrder {
		rank[s] = i
	}
	best := -1
	var out *Check
	for i := range r.Checks {
		c := &r.Checks[i]
		if c.Status != StatusFail {
			continue
		}
		if best == -1 || rank[c.Stage] < best {
			best = rank[c.Stage]
			out = c
		}
	}
	return out
}

func countWarn(checks []Check) int {
	n := 0
	for _, c := range checks {
		if c.Status == StatusWarn {
			n++
		}
	}
	return n
}

// --- stage checks ---

func engineChecks(ctx context.Context, store *storage.Store, p Params, now time.Time) []Check {
	var out []Check

	// Service liveness (systemd) — checking ladon's own unit, not routing.
	if p.ProbeService {
		svc := p.ServiceName
		if svc == "" {
			svc = "ladon"
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			out = append(out, Check{Stage: StageEngine, Status: StatusWarn,
				Title: "служба: не могу проверить", Detail: "systemctl не найден (не systemd-хост?)"})
		} else {
			state, _ := exec.CommandContext(ctx, "systemctl", "is-active", svc).Output()
			if str := trim(state); str == "active" {
				out = append(out, Check{Stage: StageEngine, Status: StatusOK,
					Title: "служба активна", Detail: svc + ".service"})
			} else {
				out = append(out, Check{Stage: StageEngine, Status: StatusFail,
					Title: "служба не активна", Detail: svc + ".service: " + str,
					Fix: "systemctl status " + svc + " ; journalctl -u " + svc + " -n 50 --no-pager"})
			}
		}
	}

	// Heartbeat freshness — the expiry sweeper stamps last_tick_at every
	// ExpiryInterval, so a stale value means the engine loop is wedged.
	stale := 2 * p.ExpiryInterval
	if stale < 90*time.Second {
		stale = 90 * time.Second
	}
	if tick, ok, terr := metaTime(ctx, store, "last_tick_at"); terr != nil {
		out = append(out, Check{Stage: StageEngine, Status: StatusWarn,
			Title: "heartbeat: ошибка чтения", Detail: terr.Error()})
	} else if !ok {
		out = append(out, Check{Stage: StageEngine, Status: StatusWarn,
			Title: "нет heartbeat", Detail: "демон не тикал с этой версии — запущен ли `ladon run`?"})
	} else if age := now.Sub(tick); age > stale {
		out = append(out, Check{Stage: StageEngine, Status: StatusFail,
			Title: "движок завис", Detail: "последний тик " + humanAge(age) + " назад",
			Fix: "journalctl -u ladon -n 50 --no-pager ; systemctl restart ladon"})
	} else {
		out = append(out, Check{Stage: StageEngine, Status: StatusOK,
			Title: "живой тик", Detail: humanAge(now.Sub(tick)) + " назад"})
	}

	// Version (informational): what the running daemon recorded vs this binary.
	if v, ok, _ := metaStr(ctx, store, "version"); ok && v != "" {
		detail := "демон " + v
		if p.Version != "" && p.Version != v {
			detail += " · этот бинарь " + p.Version
		}
		out = append(out, Check{Stage: StageEngine, Status: StatusOK, Title: "версия", Detail: detail})
	}

	return out
}

func inputChecks(ctx context.Context, store *storage.Store, now time.Time) []Check {
	var out []Check

	last, ok, err := store.LatestObservationAt(ctx)
	switch {
	case err != nil:
		out = append(out, Check{Stage: StageInput, Status: StatusWarn,
			Title: "не могу прочитать наблюдения", Detail: err.Error()})
	case !ok:
		out = append(out, Check{Stage: StageInput, Status: StatusFail,
			Title: "ладон не видит DNS", Detail: "ни одного наблюдения в базе",
			Fix: "проверь, что dnsmasq пишет лог и `log-queries` включён, а клиенты ходят через этот резолвер"})
	default:
		age := now.Sub(last)
		switch {
		case age > 15*time.Minute:
			out = append(out, Check{Stage: StageInput, Status: StatusWarn,
				Title: "давно не видел DNS", Detail: "последнее наблюдение " + humanAge(age) + " назад",
				Fix: "тихая сеть — или dnsmasq перестал писать лог (journalctl -u dnsmasq -n 20)"})
		default:
			out = append(out, Check{Stage: StageInput, Status: StatusOK,
				Title: "видит трафик", Detail: "последнее наблюдение " + humanAge(age) + " назад"})
		}
	}

	if n, err := store.CountObservationsSince(ctx, now.Add(-time.Hour)); err == nil {
		out = append(out, Check{Stage: StageInput, Status: StatusOK,
			Title: "активность за час", Detail: strconv.Itoa(n) + " доменов наблюдалось"})
	}
	return out
}

func decideChecks(ctx context.Context, store *storage.Store, now time.Time) []Check {
	var out []Check

	last, ok, err := store.LatestProbeAt(ctx)
	counts, _ := store.CountDomainsByState(ctx)
	pending := counts["new"] + counts["hot"]
	switch {
	case err != nil:
		out = append(out, Check{Stage: StageDecide, Status: StatusWarn,
			Title: "не могу прочитать пробы", Detail: err.Error()})
	case !ok:
		if pending > 0 {
			out = append(out, Check{Stage: StageDecide, Status: StatusWarn,
				Title: "проб ещё нет", Detail: strconv.Itoa(pending) + " доменов ждут пробы",
				Fix: "если это надолго — проб-воркер мог встать (journalctl -u ladon | grep prober)"})
		} else {
			out = append(out, Check{Stage: StageDecide, Status: StatusOK,
				Title: "проб ещё нет", Detail: "нет кандидатов — норма для свежего старта"})
		}
	default:
		age := now.Sub(last)
		if age > 10*time.Minute && pending > 0 {
			out = append(out, Check{Stage: StageDecide, Status: StatusWarn,
				Title: "пробы отстают", Detail: "последняя " + humanAge(age) + " назад, а кандидаты есть",
				Fix: "journalctl -u ladon | grep prober"})
		} else {
			out = append(out, Check{Stage: StageDecide, Status: StatusOK,
				Title: "пробы идут", Detail: "последняя " + humanAge(age) + " назад"})
		}
	}

	if total, blocked, clear, err := store.RecentProbeStats(ctx, now.Add(-time.Hour)); err == nil && total > 0 {
		out = append(out, Check{Stage: StageDecide, Status: StatusOK,
			Title:  "вердикты за час",
			Detail: fmt.Sprintf("%d проб (заблокировано %d, чисто %d)", total, blocked, clear)})
	}
	return out
}

func accumChecks(ctx context.Context, store *storage.Store, now time.Time) []Check {
	var out []Check

	counts, err := store.CountDomainsByState(ctx)
	if err != nil {
		return []Check{{Stage: StageAccum, Status: StatusWarn,
			Title: "не могу прочитать состояния", Detail: err.Error()}}
	}
	out = append(out, Check{Stage: StageAccum, Status: StatusOK, Title: "домены по состояниям",
		Detail: fmt.Sprintf("new %d · hot %d · cache %d · ignore %d · covered %d",
			counts["new"], counts["hot"], counts["cache"], counts["ignore"], counts["covered"])})

	active, _ := store.CountActiveHot(ctx, now)
	expired, _ := store.CountExpiredHot(ctx, now)
	hotDetail := fmt.Sprintf("%d активных", active)
	if expired > 0 {
		hotDetail += fmt.Sprintf(", %d протухших (ждут sweep)", expired)
	}
	out = append(out, Check{Stage: StageAccum, Status: StatusOK, Title: "hot", Detail: hotDetail})

	if cache, err := store.CountCacheRows(ctx); err == nil {
		out = append(out, Check{Stage: StageAccum, Status: StatusOK,
			Title: "cache", Detail: strconv.Itoa(cache) + " доменов (без TTL)"})
	}

	if orphans, err := store.CountOrphanedDomains(ctx); err == nil {
		if orphans > 0 {
			out = append(out, Check{Stage: StageAccum, Status: StatusWarn,
				Title: "orphaned домены", Detail: fmt.Sprintf("%d в hot/cache без backing-строки", orphans),
				Fix: "перезапуск чинит (ResetOrphanedDomains), либо `ladon prune -probes -dry-run`"})
		} else {
			out = append(out, Check{Stage: StageAccum, Status: StatusOK, Title: "orphaned", Detail: "0"})
		}
	}
	return out
}

func enforceChecks(ctx context.Context, store *storage.Store, p Params, now time.Time) []Check {
	var out []Check

	// How many IPs we'd expect: the size the syncer last pushed (authoritative
	// when present), falling back to "do we have any tunneled domains at all".
	expected, haveExpected, _ := metaInt(ctx, store, "ipset_engine_size")
	activeHot, _ := store.CountActiveHot(ctx, now)
	cacheRows, _ := store.CountCacheRows(ctx)
	tunneledDomains := activeHot + cacheRows

	if p.ProbeIpset && p.IpsetEngineName != "" {
		out = append(out, ipsetCheck(ctx, p.IpsetEngineName, "ladon_engine", expected, haveExpected, tunneledDomains, true)...)
		if p.IpsetManualName != "" {
			out = append(out, ipsetCheck(ctx, p.IpsetManualName, "ladon_manual", 0, false, 0, false)...)
		}
		if p.IpsetCIDRName != "" {
			out = append(out, ipsetCheck(ctx, p.IpsetCIDRName, "ladon_cidr", 0, false, 0, false)...)
		}
	}

	// Last reconcile time (from the syncer's heartbeat).
	if t, ok, terr := metaTime(ctx, store, "last_reconcile_at"); terr != nil {
		// read error — skip silently, the size check already covers health
		_ = t
	} else if ok {
		add, _, _ := metaInt(ctx, store, "reconcile_added")
		rem, _, _ := metaInt(ctx, store, "reconcile_removed")
		out = append(out, Check{Stage: StageEnforce, Status: StatusOK, Title: "reconcile",
			Detail: fmt.Sprintf("%s назад (+%d -%d)", humanAge(now.Sub(t)), add, rem)})
	} else if tunneledDomains > 0 {
		out = append(out, Check{Stage: StageEnforce, Status: StatusWarn,
			Title: "reconcile ни разу не отмечался", Detail: "синкер ещё не прошёл полный цикл?"})
	}
	return out
}

// ipsetCheck inspects one kernel set. critical=true means an empty-but-expected
// set is a hard failure (the engine set); informational sets only report size.
func ipsetCheck(ctx context.Context, name, label string, expected int, haveExpected bool, tunneledDomains int, critical bool) []Check {
	mgr := ipset.New(name)
	ok, err := mgr.Exists(ctx)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return []Check{{Stage: StageEnforce, Status: StatusWarn,
				Title: label + ": не могу проверить", Detail: "бинарь `ipset` не найден (не Linux-шлюз?)"}}
		}
		return []Check{{Stage: StageEnforce, Status: StatusWarn,
			Title: label + ": ошибка проверки", Detail: err.Error()}}
	}
	if !ok {
		st := StatusWarn
		if critical {
			st = StatusFail
		}
		return []Check{{Stage: StageEnforce, Status: st,
			Title: label + " не существует", Detail: "набор не создан в ядре",
			Fix: "ipset create " + name + " hash:ip ; systemctl restart ladon"}}
	}
	members, err := mgr.Members(ctx)
	if err != nil {
		return []Check{{Stage: StageEnforce, Status: StatusWarn,
			Title: label + ": не могу прочитать", Detail: err.Error()}}
	}
	actual := len(members)

	if critical && actual == 0 && tunneledDomains > 0 {
		detail := "ожидались IP, в наборе 0"
		if haveExpected && expected > 0 {
			detail = fmt.Sprintf("ожидалось ~%d IP, в наборе 0", expected)
		}
		return []Check{{Stage: StageEnforce, Status: StatusFail,
			Title: label + " ПУСТОЙ", Detail: detail,
			Fix: "reconcile не наполняет набор: проверь права (CAP_NET_ADMIN), `journalctl -u ladon | grep ipset`, затем `systemctl restart ladon`"}}
	}
	// Drift between what the syncer thinks it pushed and what's actually in the
	// kernel — a soft signal (a concurrent reconcile, or a manual edit).
	if critical && haveExpected && abs(actual-expected) > 5 && expected > 0 {
		return []Check{{Stage: StageEnforce, Status: StatusWarn,
			Title: label + ": расхождение", Detail: fmt.Sprintf("в ядре %d, синкер ждал %d", actual, expected)}}
	}
	return []Check{{Stage: StageEnforce, Status: StatusOK,
		Title: label, Detail: strconv.Itoa(actual) + " записей"}}
}

// --- render ---

// Render writes the human report to w in ladon's terminal style: wordmark,
// verdict badge, then every check grouped by pipeline stage.
func (r Report) Render(w io.Writer) {
	st := ui.For(w)
	st.Banner(w, ui.Subtitle("doctor", r.Version))

	switch r.Verdict {
	case StatusOK:
		st.Badge(w, ui.LevelOK, "ЗДОРОВ · ладон работает штатно")
	case StatusWarn:
		st.Badge(w, ui.LevelWarn, fmt.Sprintf("ЕСТЬ ЗАМЕЧАНИЯ · %d", countWarn(r.Checks)))
	case StatusFail:
		st.Badge(w, ui.LevelFail, "СЛОМАН · нужно вмешательство")
	}
	fmt.Fprintln(w)

	for _, stage := range stageOrder {
		group := r.stage(stage)
		if len(group) == 0 {
			continue
		}
		st.Section(w, stage)
		for _, c := range group {
			st.Row(w, uiLevel(c.Status), c.Title, c.Detail)
			if c.Status != StatusOK && c.Fix != "" {
				st.FixLine(w, c.Fix)
			}
		}
		fmt.Fprintln(w)
	}

	switch r.Verdict {
	case StatusOK:
		fmt.Fprintln(w, "  "+st.Dim("Ладон работает нормально. Если сайты всё равно не открываются,"))
		fmt.Fprintln(w, "  "+st.Dim("причина не в нём."))
	case StatusWarn:
		fmt.Fprintln(w, "  "+st.Dim("Работает, но на пункты с ▲ стоит взглянуть."))
	case StatusFail:
		if fb := r.firstBroken(); fb != nil {
			fmt.Fprintln(w, "  "+st.Red("▸ первое порванное звено: ")+st.Bold(fb.Stage+" · "+fb.Title))
			if fb.Detail != "" {
				fmt.Fprintln(w, "    "+st.Dim(fb.Detail))
			}
		}
	}
}

// uiLevel maps a doctor Status onto a ui.Level.
func uiLevel(s Status) ui.Level {
	switch s {
	case StatusWarn:
		return ui.LevelWarn
	case StatusFail:
		return ui.LevelFail
	default:
		return ui.LevelOK
	}
}

func (r Report) stage(stage string) []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Stage == stage {
			out = append(out, c)
		}
	}
	return out
}

// --- small helpers ---

func metaStr(ctx context.Context, store *storage.Store, key string) (string, bool, error) {
	row, ok, err := store.GetMeta(ctx, key)
	if err != nil || !ok {
		return "", ok, err
	}
	return row.Value, true, nil
}

func metaInt(ctx context.Context, store *storage.Store, key string) (int, bool, error) {
	v, ok, err := metaStr(ctx, store, key)
	if err != nil || !ok {
		return 0, ok, err
	}
	n, perr := strconv.Atoi(v)
	if perr != nil {
		return 0, false, perr
	}
	return n, true, nil
}

// metaTime returns (parsed, found, err). On a read or parse error, err is set
// (callers treat it as a soft warning).
func metaTime(ctx context.Context, store *storage.Store, key string) (time.Time, bool, error) {
	row, ok, err := store.GetMeta(ctx, key)
	if err != nil {
		return time.Time{}, false, err
	}
	if !ok {
		return time.Time{}, false, nil
	}
	t, valid, perr := storage.ParseTime(row.Value)
	if perr != nil {
		return time.Time{}, false, perr
	}
	if !valid {
		return time.Time{}, false, nil
	}
	return t, true, nil
}

func humanAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "с"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "м"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "ч"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + "д"
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func trim(b []byte) string {
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
