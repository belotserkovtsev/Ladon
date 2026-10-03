package ipset

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestExistsHelperProcess is not a test of its own: the cases below run it as a
// separate process to get a real exit status, the kind the set tools return.
func TestExistsHelperProcess(t *testing.T) {
	if os.Getenv("LADON_EXISTS_HELPER") != "1" {
		return
	}
	os.Exit(1)
}

// failedRun returns the error of a process that exited with status 1.
func failedRun(t *testing.T) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestExistsHelperProcess$")
	cmd.Env = append(os.Environ(), "LADON_EXISTS_HELPER=1")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("helper did not exit with a status: %v", err)
	}
	return err
}

// TestExistsResult — only the tool saying the set does not exist means it is
// absent. A refusal to look is an error: read as "absent", it had doctor tell
// anyone without root to recreate a set that was there.
func TestExistsResult(t *testing.T) {
	cases := []struct {
		name, tool, stderr string
		wantErr            string // substring of the error; "" means none
	}{
		{"ipset: set missing", "ipset", "ipset v7.17: The set with the given name does not exist\n", ""},
		{"ipset: no permission", "ipset", "ipset v7.17: Kernel error received: Operation not permitted\n", "Operation not permitted"},
		{"pfctl: table missing", "pfctl", "pfctl: Table does not exist.\n", ""},
		{"pfctl: no permission", "pfctl", "pfctl: /dev/pf: Permission denied\n", "Permission denied"},
		{"failed without a word", "ipset", "", "exit status 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := existsResult(c.tool, "ladon_engine", failedRun(t), c.stderr)
			if ok {
				t.Fatal("a failed command must never report the set as present")
			}
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("err=%v, want none: the set is simply absent", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("err=%v, want one naming %q: the set could not be looked at", err, c.wantErr)
			}
		})
	}
}

func TestExistsResult_PresentAndToolMissing(t *testing.T) {
	if ok, err := existsResult("ipset", "ladon_engine", nil, ""); !ok || err != nil {
		t.Errorf("success: ok=%v err=%v, want present", ok, err)
	}
	// doctor tells "the tool is not installed" apart by exec.ErrNotFound, so the
	// error must come back as it was.
	notFound := &exec.Error{Name: "ipset", Err: exec.ErrNotFound}
	if ok, err := existsResult("ipset", "ladon_engine", notFound, ""); ok || !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("missing tool: ok=%v err=%v, want exec.ErrNotFound", ok, err)
	}
}
