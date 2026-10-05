package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRuleValidation(t *testing.T) {
	for _, r := range []rule{
		{"allow", "tcp", "0", "any", ""}, {"allow", "tcp", "65536", "any", ""},
		{"allow", "tcp", "100:1", "any", ""}, {"allow", "tcp", "22; reboot", "any", ""},
		{"allow", "udp", "53", "--force", ""}, {"allow", "tcp", "22", "host.example", ""},
		{"allow", "tcp", "22", "fe80::1%eth0", ""}, {"allow", "tcp", "22", "any", "bad\ncomment"},
		{"allow", "tcp", "22", "any", "bad\x1bcomment"}, {"limit", "udp", "53", "any", ""},
	} {
		if _, e := r.args(); e == nil {
			t.Fatalf("accepted unsafe/invalid rule: %+v", r)
		}
	}
	for _, r := range []rule{{"allow", "tcp", "22", "192.0.2.7", "SSH"}, {"deny", "udp", "8000:8010", "2001:db8::/32", ""}, {"limit", "tcp", "22", "any", "SSH"}} {
		if _, e := r.args(); e != nil {
			t.Fatal(e)
		}
	}
}
func TestLiteralArgumentsAndCIDR(t *testing.T) {
	args, e := (rule{"allow", "tcp", "443", "192.0.2.7/24", "$(touch /tmp/x)"}).args()
	if e != nil {
		t.Fatal(e)
	}
	want := []string{"allow", "in", "proto", "tcp", "from", "192.0.2.0/24", "to", "any", "port", "443", "comment", "$(touch /tmp/x)"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("%v", args)
	}
}
func TestNumberAndFamily(t *testing.T) {
	text := "Status: active\n[ 1] 22/tcp ALLOW IN Anywhere # (v6) comment\n[12] 22/tcp (v6) ALLOW IN Anywhere (v6)"
	a, e := numberedLine(text, "1")
	if e != nil {
		t.Fatal(e)
	}
	b, e := numberedLine(text, "12")
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"0", "2", "01", "1;id", "-1"} {
		if _, e := numberedLine(text, n); e == nil {
			t.Fatal(n)
		}
	}
	if e := editFamily(a, "0.0.0.0/0"); e != nil {
		t.Fatal(e)
	}
	if e := editFamily(b, "::/0"); e != nil {
		t.Fatal(e)
	}
	for _, source := range []string{"any", "", "192.0.2.0/24"} {
		if e := editFamily(b, source); e == nil {
			t.Fatal(source)
		}
	}
}

type fake struct {
	a                            *app
	active, failTimer, failApply bool
	calls                        []string
}

func fixture(t *testing.T) *fake {
	t.Helper()
	base := t.TempDir()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	a := &app{state: filepath.Join(base, "state"), etc: filepath.Join(base, "etc"), now: func() time.Time { return now }, ssh: "192.0.2.1 1000 192.0.2.2 22"}
	for _, d := range []string{"ufw", "default"} {
		if e := os.MkdirAll(filepath.Join(a.etc, d), 0700); e != nil {
			t.Fatal(e)
		}
	}
	for _, p := range []string{"ufw/user.rules", "ufw/user6.rules", "ufw/ufw.conf", "default/ufw"} {
		if e := os.WriteFile(filepath.Join(a.etc, p), []byte("original "+p), 0600); e != nil {
			t.Fatal(e)
		}
	}
	f := &fake{a: a, active: true}
	a.run = f.run
	if e := a.init(); e != nil {
		t.Fatal(e)
	}
	return f
}
func copyTest(source, dest string) error {
	st, e := os.Stat(source)
	if e != nil {
		return e
	}
	if !st.IsDir() {
		b, e := os.ReadFile(source)
		if e != nil {
			return e
		}
		return os.WriteFile(dest, b, 0600)
	}
	if e = os.MkdirAll(dest, 0700); e != nil {
		return e
	}
	entries, e := os.ReadDir(source)
	if e != nil {
		return e
	}
	for _, v := range entries {
		if e = copyTest(filepath.Join(source, v.Name()), filepath.Join(dest, v.Name())); e != nil {
			return e
		}
	}
	return nil
}
func (f *fake) run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "cp":
		return "", copyTest(args[len(args)-2], args[len(args)-1])
	case "systemctl":
		if args[0] == "is-enabled" {
			return "enabled\n", nil
		}
		return "", nil
	case "systemd-run":
		if f.failTimer {
			return "", errors.New("timer unavailable")
		}
		return "", nil
	case "ufw":
		if args[0] == "status" {
			if f.active {
				return "Status: active\n", nil
			}
			return "Status: inactive\n", nil
		}
		if args[0] == "--force" {
			f.active = args[1] == "enable"
			return "", nil
		}
		if f.failApply {
			f.failApply = false
			return "", errors.New("ufw failed")
		}
		return "", nil
	}
	return "", errors.New("unexpected command")
}
func applyFixture(f *fake) (*pending, error) {
	return f.a.change("test", func() error {
		return os.WriteFile(filepath.Join(f.a.etc, "ufw", "user.rules"), []byte("changed"), 0600)
	})
}
func TestTimerFailurePreventsMutation(t *testing.T) {
	f := fixture(t)
	f.failTimer = true
	called := false
	if _, e := f.a.change("test", func() error { called = true; return nil }); e == nil {
		t.Fatal("expected error")
	}
	if called {
		t.Fatal("changed firewall without timer")
	}
	if p, e := f.a.getPending(); e != nil || p != nil {
		t.Fatalf("pending %v %v", p, e)
	}
}
func TestRollbackRestoresWholeConfigurationAndActiveState(t *testing.T) {
	f := fixture(t)
	p, e := applyFixture(f)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.a.etc, "ufw", "extra.rules"), []byte("extra"), 0600); e != nil {
		t.Fatal(e)
	}
	f.active = false
	if e = f.a.rollback(); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(f.a.etc, "ufw", "user.rules"))
	if e != nil || string(b) != "original ufw/user.rules" {
		t.Fatalf("restore %s %v", b, e)
	}
	if _, e = os.Stat(filepath.Join(f.a.etc, "ufw", "extra.rules")); !os.IsNotExist(e) {
		t.Fatal("extra file retained")
	}
	if !f.active {
		t.Fatal("did not re-enable original active firewall")
	}
	if _, e = f.a.loadSnapshot(p.Snapshot); e != nil {
		t.Fatal("backup lost", e)
	}
	if pending, e := f.a.getPending(); e != nil || pending != nil {
		t.Fatal("pending retained")
	}
	// Late timer callback after completed rollback is harmless.
	if e = f.a.rollback(); e != nil {
		t.Fatal(e)
	}
}
func TestRollbackRestoresInactiveState(t *testing.T) {
	f := fixture(t)
	f.active = false
	if _, e := applyFixture(f); e != nil {
		t.Fatal(e)
	}
	f.active = true
	if e := f.a.rollback(); e != nil {
		t.Fatal(e)
	}
	if f.active {
		t.Fatal("original inactive firewall was enabled")
	}
}
func TestApplyErrorRollsBackImmediately(t *testing.T) {
	f := fixture(t)
	_, e := f.a.change("partial failure", func() error {
		os.WriteFile(filepath.Join(f.a.etc, "ufw", "user.rules"), []byte("partial"), 0600)
		return errors.New("failed")
	})
	if e == nil {
		t.Fatal("expected error")
	}
	b, _ := os.ReadFile(filepath.Join(f.a.etc, "ufw", "user.rules"))
	if string(b) != "original ufw/user.rules" {
		t.Fatal("not restored")
	}
}
func TestConfirmRequiresNewSSHAndCorrectToken(t *testing.T) {
	f := fixture(t)
	p, e := applyFixture(f)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.a.confirm(p.Token); e == nil {
		t.Fatal("same connection accepted")
	}
	f.a.ssh = ""
	if e = f.a.confirm(p.Token); e == nil {
		t.Fatal("missing connection accepted")
	}
	f.a.ssh = "192.0.2.1 2000 192.0.2.2 22"
	if e = f.a.confirm("bad"); e == nil {
		t.Fatal("bad token accepted")
	}
	if e = f.a.confirm(p.Token); e != nil {
		t.Fatal(e)
	}
	if e = f.a.rollback(); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(f.a.etc, "ufw", "user.rules"))
	if string(b) != "changed" {
		t.Fatal("late rollback undid confirmed changes")
	}
}
func TestPendingBlocksAnotherChangeAndExpiredConfirmation(t *testing.T) {
	f := fixture(t)
	p, e := applyFixture(f)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = applyFixture(f); e == nil {
		t.Fatal("second mutation allowed")
	}
	f.a.ssh = "new connection"
	f.a.now = func() time.Time { return p.Deadline }
	if e = f.a.confirm(p.Token); e == nil {
		t.Fatal("expired confirmation allowed")
	}
	if e = f.a.rollback(); e != nil {
		t.Fatal(e)
	}
}
func TestMalformedStateAndTraversalRejected(t *testing.T) {
	f := fixture(t)
	if _, e := f.a.loadSnapshot("../../etc"); e == nil {
		t.Fatal("traversal")
	}
	if e := os.WriteFile(filepath.Join(f.a.state, "pending.json"), []byte(`{"snapshot":"../../etc","token":"x"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := applyFixture(f); e == nil {
		t.Fatal("corrupt pending accepted")
	}
}

func TestIncompleteApplyCannotBeConfirmed(t *testing.T) {
	f := fixture(t)
	p, e := applyFixture(f)
	if e != nil {
		t.Fatal(e)
	}
	p.Ready = false
	if e = writeJSON(filepath.Join(f.a.state, "pending.json"), p); e != nil {
		t.Fatal(e)
	}
	f.a.ssh = "new connection"
	if e = f.a.confirm(p.Token); e == nil {
		t.Fatal("incomplete apply confirmed")
	}
}
func TestRecoveryFailureRetainsPendingForRetry(t *testing.T) {
	f := fixture(t)
	if _, e := applyFixture(f); e != nil {
		t.Fatal(e)
	}
	originalRun := f.a.run
	fail := true
	f.a.run = func(name string, args ...string) (string, error) {
		if name == "cp" && fail {
			fail = false
			return "", errors.New("disk unavailable")
		}
		return originalRun(name, args...)
	}
	if e := f.a.rollback(); e == nil {
		t.Fatal("expected restore failure")
	}
	if p, e := f.a.getPending(); e != nil || p == nil {
		t.Fatal("lost pending state")
	}
	// A new application process after reboot reads the same persisted state.
	recovered := &app{state: f.a.state, etc: f.a.etc, run: originalRun, now: f.a.now}
	if e := recovered.rollback(); e != nil {
		t.Fatal(e)
	}
	if p, e := recovered.getPending(); e != nil || p != nil {
		t.Fatal("retry did not finish")
	}
}
func TestComplexRulesCannotBeSilentlyConverted(t *testing.T) {
	for _, line := range []string{"[1] 25/tcp ALLOW OUT Anywhere", "[1] 25/tcp ALLOW FWD Anywhere", "[1] 25/tcp on eth0 ALLOW IN Anywhere"} {
		if e := editFamily(line, "0.0.0.0/0"); e == nil {
			t.Fatal(line)
		}
	}
}
