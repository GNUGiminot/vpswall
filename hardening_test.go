package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSSHSourceModesAndLockWarning(t *testing.T) {
	for _, tc := range []struct{ conn, mode, want string }{
		{"203.0.113.77 1000 192.0.2.2 22", "", "any"},
		{"203.0.113.77 1000 192.0.2.2 22", "any", "any"},
		{"203.0.113.77 1000 192.0.2.2 22", "subnet", "203.0.113.0/24"},
		{"203.0.113.77 1000 192.0.2.2 22", "ip", "203.0.113.77"},
		{"2001:db8:1:2:3:4:5:6 1000 2001:db8::1 22", "subnet", "2001:db8:1:2::/64"},
	} {
		got, e := sshSource(tc.conn, tc.mode)
		if e != nil || got != tc.want {
			t.Fatal(tc, got, e)
		}
	}
	if _, e := sshSource("203.0.113.77 1000 192.0.2.2 22", "everything"); e == nil {
		t.Fatal("unknown mode accepted")
	}
	c := managerConfig{Backend: "ufw", Zone: "public", Enabled: true, Policy: "deny"}
	c, e := keepSSH(c, "203.0.113.77 1000 192.0.2.2 22", "")
	if e != nil || len(c.Rules) != 1 || c.Rules[0].Source != "any" || c.Rules[0].Port != "22" {
		t.Fatal(c, e)
	}
	if w := sshLockWarning(c, "22"); w != "" {
		t.Fatal("any-rule warned:", w)
	}
	// An existing any-rule already covers a narrower request.
	if again, _ := keepSSH(c, "203.0.113.77 1000 192.0.2.2 22", "ip"); len(again.Rules) != 1 {
		t.Fatal("duplicate SSH rule", again.Rules)
	}
	locked, _ := keepSSH(managerConfig{Backend: "ufw", Zone: "public", Enabled: true, Policy: "deny"}, "203.0.113.77 1000 192.0.2.2 22", "ip")
	if w := sshLockWarning(locked, "22"); !strings.Contains(w, "203.0.113.77") {
		t.Fatal("no lock warning:", w)
	}
	locked.Policy = "allow"
	if sshLockWarning(locked, "22") != "" {
		t.Fatal("warning with permissive policy")
	}
	if !portCovers("20:30", "22") || portCovers("23:30", "22") || !portCovers("22", "22") {
		t.Fatal("port range")
	}
}

func TestTUIKeepSSHDefaultsToAllAddresses(t *testing.T) {
	m := managerFixture(t)
	c, _ := m.config()
	c.Enabled = false
	writeJSON(m.path("manager.json"), c)
	u := newUI(m)
	u.open("ssh-choice")
	if u.items[0].id != "any" || u.items[2].id != "ip" || !strings.Contains(u.items[2].description, "РИСК") {
		t.Fatal(u.items)
	}
	u.activate()
	if !strings.Contains(u.reviewText, "со всех адресов") {
		t.Fatal(u.reviewText)
	}
	// The TUI now passes the revision: a concurrent edit makes the review fail.
	other := c
	other.Policy = "allow"
	writeJSON(m.path("manager.json"), other)
	if _, e := u.reviewAction(); e == nil || !strings.Contains(e.Error(), "другом сеансе") {
		t.Fatal("stale TUI change applied", e)
	}
}

func TestWebSSHSourceDefaultsToAnyAndAcceptsIP(t *testing.T) {
	for _, tc := range []struct{ source, want string }{{"", "any"}, {"ip", "192.0.2.1"}, {"subnet", "192.0.2.0/24"}} {
		s, _ := webFixture(t)
		m := s.m
		c, _ := m.config()
		c.Enabled = false
		writeJSON(m.path("manager.json"), c)
		if _, _, e := s.action(m, webAction{Op: "toggle", Enabled: true, SSHSource: tc.source, Revision: configRevision(c)}); e != nil {
			t.Fatal(e)
		}
		after, _ := m.config()
		if len(after.Rules) != 1 || after.Rules[0].Source != tc.want {
			t.Fatal(tc, after.Rules)
		}
	}
}

func TestConfirmRequiresSessionStartedAfterChange(t *testing.T) {
	m := managerFixture(t)
	c, _ := m.config()
	c.Policy = "allow"
	p, e := m.change("policy", c)
	if e != nil {
		t.Fatal(e)
	}
	m.ssh = "192.0.2.1 2000 192.0.2.2 22" // a different connection...
	m.sessionStart = func() (time.Time, error) { return p.Created.Add(-time.Minute), nil }
	if e = m.confirm(p.Token); e == nil || !strings.Contains(e.Error(), "до изменения") {
		t.Fatal("session opened before the change confirmed it", e)
	}
	m.sessionStart = func() (time.Time, error) { return time.Time{}, errors.New("tmux") }
	if e = m.confirm(p.Token); e == nil || !strings.Contains(e.Error(), "tmux") {
		t.Fatal("unknown session confirmed", e)
	}
	m.demo = false
	m.sessionStart = nil
	if e = m.confirm(p.Token); e == nil {
		t.Fatal("production without session check confirmed")
	}
	m.demo = true
	m.sessionStart = func() (time.Time, error) { return p.Created.Add(5 * time.Second), nil }
	if e = m.confirm(p.Token); e != nil {
		t.Fatal(e)
	}
}

func writeProcStat(t *testing.T, proc string, pid, ppid int, comm string, start int64) {
	t.Helper()
	dir := filepath.Join(proc, strconv.Itoa(pid))
	os.MkdirAll(dir, 0755)
	line := fmt.Sprintf("%d (%s) S %d%s %d 0 0\n", pid, comm, ppid, strings.Repeat(" 0", 17), start)
	if e := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0644); e != nil {
		t.Fatal(e)
	}
}
func TestProcSessionStartFindsNearestSSHD(t *testing.T) {
	proc := t.TempDir()
	os.WriteFile(filepath.Join(proc, "stat"), []byte("cpu 1 2 3\nbtime 1700000000\nprocesses 5\n"), 0644)
	writeProcStat(t, proc, 1, 0, "systemd", 1)
	writeProcStat(t, proc, 100, 1, "sshd", 50)              // listener, started at boot
	writeProcStat(t, proc, 150, 100, "sshd-session", 9000)  // privileged monitor
	writeProcStat(t, proc, 160, 150, "sshd-session", 12345) // user session
	writeProcStat(t, proc, 200, 160, "bash (login)", 12400) // comm with spaces and parens
	writeProcStat(t, proc, 300, 200, "sudo", 20000)
	writeProcStat(t, proc, 301, 300, "vpswall", 20001)
	got, e := procSessionStart(proc, 301)
	want := time.Unix(1700000000, 0).Add(123450 * time.Millisecond)
	if e != nil || !got.Equal(want) {
		t.Fatal(got, want, e)
	}
	writeProcStat(t, proc, 400, 1, "tmux: server", 60)
	writeProcStat(t, proc, 401, 400, "bash", 70)
	writeProcStat(t, proc, 402, 401, "vpswall", 80)
	if _, e = procSessionStart(proc, 402); e == nil {
		t.Fatal("tmux session accepted")
	}
}

// fakeNFT keeps the inet vpswall table as the last loaded script.
type fakeNFT struct {
	table    string
	applies  int
	ufwOn    bool
	failLoad bool
}

func (f *fakeNFT) run(name string, args ...string) (string, error) {
	all := strings.Join(args, " ")
	switch {
	case name == "ufw" && all == "status":
		if f.ufwOn {
			return "Status: active\n", nil
		}
		return "Status: inactive\n", nil
	case name == "nft" && all == "-j list ruleset":
		return `{"nftables":[]}`, nil
	case name == "nft" && all == "-j list table inet vpswall":
		if f.table == "" {
			return "", errors.New("nft: Error: No such file or directory")
		}
		return `{"nftables":[{"table":{"family":"inet","name":"vpswall","comment":"VPSWall managed"}},{"rule":{"comment":` + strconv.Quote(f.table) + `}}]}`, nil
	case name == "nft" && len(args) == 2 && args[0] == "-f":
		if f.failLoad {
			return "", errors.New("nft: load failed")
		}
		data, e := os.ReadFile(args[1])
		if e != nil {
			return "", e
		}
		f.applies++
		f.table = ""
		if strings.Contains(string(data), "table inet vpswall {") {
			f.table = string(data)
		}
	}
	return "", nil
}
func nftFixture(t *testing.T) (*manager, *fakeNFT, managedRule) {
	t.Helper()
	m := managerFixture(t)
	m.demo = false
	fake := &fakeNFT{}
	m.run = fake.run
	r, _ := newManaged("allow", "tcp", "443", "any", "Web")
	c := managerConfig{Backend: "nftables", Zone: "public", Enabled: true, Policy: "deny", Rules: []managedRule{r}}
	if e := writeJSON(m.path("manager.json"), c); e != nil {
		t.Fatal(e)
	}
	return m, fake, r
}

func TestDriftReappliesRulesRemovedBehindVPSWall(t *testing.T) {
	m, fake, r := nftFixture(t)
	if e := m.worker(false); e != nil || fake.applies != 1 || !strings.Contains(fake.table, "VPSWall:"+r.ID) {
		t.Fatal(e, fake.applies)
	}
	if e := m.worker(false); e != nil || fake.applies != 1 {
		t.Fatal("unchanged rules reapplied", e, fake.applies)
	}
	fake.table = "" // nft flush ruleset / firewall reload
	if e := m.worker(false); e != nil || fake.applies != 2 || !strings.Contains(fake.table, "VPSWall:"+r.ID) {
		t.Fatal("drift not repaired", e, fake.applies)
	}
	history, _ := os.ReadFile(m.path("history.log"))
	if !strings.Contains(string(history), "DRIFT") {
		t.Fatal("drift not logged:", string(history))
	}
}

func TestExpiredWindowClosesDespiteForeignFirewall(t *testing.T) {
	m, fake, _ := nftFixture(t)
	w, _ := newManaged("allow", "tcp", "8080", "any", "Окно")
	start := m.now().Add(-10 * time.Minute)
	writeJSON(m.path("windows.json"), []window{{ID: w.ID, Rule: w, Kind: "lease", Start: start, Seconds: 3600}})
	if e := m.worker(false); e != nil || !strings.Contains(fake.table, "VPSWall:"+w.ID) {
		t.Fatal("window not opened", e)
	}
	fake.ufwOn = true // e.g. another firewall appeared after the window opened
	m.now = func() time.Time { return start.Add(2 * time.Hour) }
	if e := m.worker(false); e != nil {
		t.Fatal("closing blocked by conflict:", e)
	}
	if strings.Contains(fake.table, "VPSWall:"+w.ID) {
		t.Fatal("expired window still open")
	}
	if a := m.alert(); !strings.Contains(a, "Конфликт") {
		t.Fatal("conflict not signalled:", a)
	}
	// Opening anything through the conflict stays refused.
	w2, _ := newManaged("allow", "tcp", "9090", "any", "Окно")
	writeJSON(m.path("windows.json"), []window{{ID: w2.ID, Rule: w2, Kind: "lease", Start: m.now(), Seconds: 3600}})
	if e := m.worker(false); e == nil || strings.Contains(fake.table, "VPSWall:"+w2.ID) {
		t.Fatal("window opened through conflict", e)
	}
}

func TestFailedWindowCloseRaisesAlertUntilFixed(t *testing.T) {
	m, fake, _ := nftFixture(t)
	w, _ := newManaged("allow", "tcp", "8080", "any", "Окно")
	start := m.now().Add(-10 * time.Minute)
	writeJSON(m.path("windows.json"), []window{{ID: w.ID, Rule: w, Kind: "lease", Start: start, Seconds: 3600}})
	if e := m.worker(false); e != nil {
		t.Fatal(e)
	}
	fake.failLoad = true
	m.now = func() time.Time { return start.Add(2 * time.Hour) }
	if e := m.worker(false); e == nil {
		t.Fatal("failure hidden")
	}
	if a := m.alert(); !strings.Contains(a, "8080/tcp не закрыто") {
		t.Fatal("no alert:", a)
	}
	m.worker(false) // the same failure is logged once
	history, _ := os.ReadFile(m.path("history.log"))
	if strings.Count(string(history), "ALERT Окно") != 1 {
		t.Fatal("alert spam:", string(history))
	}
	s, _ := webFixture(t)
	s.m.root = m.root
	if state, e := s.state(s.m); e != nil || !strings.Contains(state.Alert, "8080") {
		t.Fatal("alert not in web state", state.Alert, e)
	}
	fake.failLoad = false
	if e := m.worker(false); e != nil || m.alert() != "" {
		t.Fatal("alert not cleared", e, m.alert())
	}
}

// fakeUFW tracks VPSWall rules by their comment and counts mutations.
type fakeUFW struct {
	ids              []string
	prepends, delete int
}

func ufwID(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "VPSWall:") {
			return a
		}
	}
	return ""
}
func (f *fakeUFW) run(name string, args ...string) (string, error) {
	if name != "ufw" {
		return "", nil
	}
	all := strings.Join(args, " ")
	switch {
	case all == "show added":
		return "Added user rules:\n" + strings.Join(f.ids, "\n"), nil
	case strings.HasPrefix(all, "status"):
		return "Status: active\nDefault: deny (incoming), allow (outgoing)\n", nil
	case args[0] == "prepend":
		f.prepends++
		f.ids = append([]string{ufwID(args)}, f.ids...)
	case args[0] == "--force" && args[1] == "delete":
		f.delete++
		id := ufwID(args)
		kept := f.ids[:0]
		for _, v := range f.ids {
			if v != id {
				kept = append(kept, v)
			}
		}
		f.ids = kept
	}
	return "", nil
}
func TestUFWWindowsChangeOnlyTheirOwnRules(t *testing.T) {
	m := managerFixture(t)
	m.demo = false
	fake := &fakeUFW{}
	m.run = fake.run
	a, _ := newManaged("allow", "tcp", "443", "any", "Web")
	b, _ := newManaged("allow", "tcp", "80", "any", "HTTP")
	c := managerConfig{Backend: "ufw", Zone: "public", Enabled: true, Policy: "deny", Rules: []managedRule{a, b}}
	writeJSON(m.path("manager.json"), c)
	if e := m.synchronize(c, true); e != nil || fake.prepends != 2 {
		t.Fatal(e, fake)
	}
	w, _ := newManaged("allow", "tcp", "8080", "any", "Окно")
	start := m.now()
	writeJSON(m.path("windows.json"), []window{{ID: w.ID, Rule: w, Kind: "lease", Start: start, Seconds: 3600}})
	fake.prepends, fake.delete = 0, 0
	if e := m.synchronize(c, true); e != nil || fake.prepends != 1 || fake.delete != 0 || fake.ids[0] != "VPSWall:"+w.ID {
		t.Fatal("window open rebuilt rules", e, *fake)
	}
	m.now = func() time.Time { return start.Add(2 * time.Hour) }
	fake.prepends, fake.delete = 0, 0
	if e := m.synchronize(c, true); e != nil || fake.prepends != 0 || fake.delete != 1 || len(fake.ids) != 2 {
		t.Fatal("window close rebuilt rules", e, *fake)
	}
	// Removing a permanent rule deletes only that rule.
	c.Rules = c.Rules[:1]
	fake.prepends, fake.delete = 0, 0
	if e := m.synchronize(c, true); e != nil || fake.delete != 1 || fake.prepends != 0 || len(fake.ids) != 1 {
		t.Fatal("permanent removal", e, *fake)
	}
	// Adding or editing a permanent rule rebuilds in priority order.
	edited := c.Rules[0]
	edited.Port = "8443"
	c.Rules = []managedRule{edited}
	fake.prepends, fake.delete = 0, 0
	if e := m.synchronize(c, true); e != nil || fake.delete != 1 || fake.prepends != 1 || len(fake.ids) != 1 {
		t.Fatal("permanent edit", e, *fake)
	}
	// ufw reset is detected as drift and repaired.
	fake.ids = nil
	if drift := m.verifyBackend(c, c.Rules); drift == "" {
		t.Fatal("ufw reset not detected")
	}
}

func TestWebUnitIsHardened(t *testing.T) {
	m := managerFixture(t)
	m.demo = false
	m.run = func(name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "is-active" {
			return "active\n", nil
		}
		return "enabled\n", nil
	}
	if e := m.webService(true); e != nil {
		t.Fatal(e)
	}
	unit, _ := os.ReadFile(filepath.Join(m.system, "systemd", "system", "vpswall-web.service"))
	for _, want := range []string{"NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectHome=yes"} {
		if !strings.Contains(string(unit), want) {
			t.Fatal(want, string(unit))
		}
	}
}
