package ipset

import (
	"context"
	"sort"
	"testing"
)

// fakeBackend records what Reconcile asked it to change.
type fakeBackend struct {
	current []string
	adds    []string
	dels    []string
}

func (f *fakeBackend) exists(context.Context, string) (bool, error) { return true, nil }
func (f *fakeBackend) members(context.Context, string) ([]string, error) {
	return append([]string(nil), f.current...), nil
}
func (f *fakeBackend) add(_ context.Context, _, ip string) error {
	f.adds = append(f.adds, ip)
	return nil
}
func (f *fakeBackend) del(_ context.Context, _, ip string) error {
	f.dels = append(f.dels, ip)
	return nil
}
func (f *fakeBackend) save(context.Context, string) ([]byte, error) { return nil, nil }

func newFake(current ...string) (*Manager, *fakeBackend) {
	be := &fakeBackend{current: current}
	return &Manager{Name: "test", be: be}, be
}

// A host pinned as /32 is reported back by the set without the prefix. Before
// this was handled, every pass added the /32 form and deleted the bare one —
// the same address — so the entry vanished and the operator's pin silently
// stopped routing.
func TestReconcileTreatsFullPrefixAsBareAddress(t *testing.T) {
	m, be := newFake("130.255.77.28", "91.108.4.0/22")

	added, removed, err := m.Reconcile(context.Background(),
		[]string{"130.255.77.28/32", "91.108.4.0/22"})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || removed != 0 {
		t.Fatalf("want no changes, got added=%d removed=%d (adds=%v dels=%v)",
			added, removed, be.adds, be.dels)
	}
	if len(be.adds) != 0 || len(be.dels) != 0 {
		t.Fatalf("backend touched: adds=%v dels=%v", be.adds, be.dels)
	}
}

// The same equivalence in reverse: the file says the bare address, the set
// reports a /32.
func TestReconcileTreatsBareAddressAsFullPrefix(t *testing.T) {
	m, be := newFake("130.255.77.28/32")
	added, removed, err := m.Reconcile(context.Background(), []string{"130.255.77.28"})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || removed != 0 {
		t.Fatalf("want no changes, got added=%d removed=%d (adds=%v dels=%v)",
			added, removed, be.adds, be.dels)
	}
}

// A network written with host bits set matches the base address the set stores.
func TestReconcileMasksNetworkHostBits(t *testing.T) {
	m, _ := newFake("10.0.0.0/24")
	added, removed, err := m.Reconcile(context.Background(), []string{"10.0.0.5/24"})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || removed != 0 {
		t.Fatalf("want no changes, got added=%d removed=%d", added, removed)
	}
}

// Genuine differences must still be applied, and with the caller's syntax.
func TestReconcileStillAddsAndRemoves(t *testing.T) {
	m, be := newFake("10.0.0.1", "192.0.2.0/24")

	added, removed, err := m.Reconcile(context.Background(),
		[]string{"10.0.0.1/32", "198.51.100.7/32"})
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || removed != 1 {
		t.Fatalf("want added=1 removed=1, got added=%d removed=%d", added, removed)
	}
	if len(be.adds) != 1 || be.adds[0] != "198.51.100.7/32" {
		t.Errorf("adds=%v want [198.51.100.7/32] (caller's syntax preserved)", be.adds)
	}
	if len(be.dels) != 1 || be.dels[0] != "192.0.2.0/24" {
		t.Errorf("dels=%v want [192.0.2.0/24]", be.dels)
	}
}

func TestCanonical(t *testing.T) {
	cases := map[string]string{
		"130.255.77.28":    "130.255.77.28",
		"130.255.77.28/32": "130.255.77.28",
		"91.108.4.0/22":    "91.108.4.0/22",
		"10.0.0.5/24":      "10.0.0.0/24",
		"2001:db8::1/128":  "2001:db8::1",
		"2001:db8::/32":    "2001:db8::/32",
		"not-an-address":   "not-an-address",
	}
	keys := make([]string, 0, len(cases))
	for in := range cases {
		keys = append(keys, in)
	}
	sort.Strings(keys)
	for _, in := range keys {
		if got := canonical(in); got != cases[in] {
			t.Errorf("canonical(%q) = %q, want %q", in, got, cases[in])
		}
	}
}
