package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func managerFixture(t *testing.T) *manager {
	t.Helper()
	root := t.TempDir()
	now := time.Date(2026, 10, 5, 0, 30, 0, 0, time.UTC)
	m := &manager{root: root, system: filepath.Join(root, "etc"), runtimeDir: filepath.Join(root, "run"), now: func() time.Time { return now }, ssh: "192.0.2.1 1000 192.0.2.2 22", demo: true}
	m.run = func(name string, args ...string) (string, error) {
		if name == "systemctl" {
			return "enabled\n", nil
		}
		return "", nil
	}
	c := managerConfig{Backend: "ufw", Enabled: true, Zone: "public", Policy: "deny"}
	if e := writeJSON(m.path("manager.json"), c); e != nil {
		t.Fatal(e)
	}
	return m
}
func TestWindowDailyCrossesMidnightAndTimeZone(t *testing.T) {
	r, _ := newManaged("allow", "tcp", "80", "any", "test")
	w := window{ID: r.ID, Rule: r, Kind: "daily", Clock: "23:30", Zone: "Europe/Moscow", Seconds: 7200}
	if e := w.validate(); e != nil {
		t.Fatal(e)
	}
	before := time.Date(2026, 10, 5, 21, 15, 0, 0, time.UTC)
	start, end, active := w.interval(before)
	if !active || start.Hour() != 23 || end.Day() != 6 {
		t.Fatal(start, end, active)
	}
	if _, _, active = w.interval(end); active {
		t.Fatal("inclusive end")
	}
	if !w.next(end).After(end) {
		t.Fatal("invalid next occurrence")
	}
	w.Paused = true
	if _, _, active = w.interval(before); active {
		t.Fatal("paused window active")
	}
}
func TestWindowRestartSkipsMissedOnceAndExpiresLease(t *testing.T) {
	m := managerFixture(t)
	r, _ := newManaged("allow", "tcp", "80", "any", "test")
	w := window{ID: r.ID, Rule: r, Kind: "once", Start: m.now().Add(-2 * time.Hour), Seconds: 3600}
	writeJSON(m.path("windows.json"), []window{w})
	c, _ := m.config()
	desired, e := m.desired(c)
	if e != nil || len(desired) != 0 {
		t.Fatal(desired, e)
	}
	w.Kind = "lease"
	w.Start = m.now().Add(-30 * time.Minute)
	writeJSON(m.path("windows.json"), []window{w})
	desired, e = m.desired(c)
	if e != nil || len(desired) != 1 || !desired[0].Temporary {
		t.Fatal(desired, e)
	}
	m.now = func() time.Time { return w.Start.Add(time.Hour) }
	desired, e = m.desired(c)
	if e != nil || len(desired) != 0 {
		t.Fatal(desired, e)
	}
}
func TestWindowValidationRejectsUnsafeAndAlwaysOpenSchedule(t *testing.T) {
	r, _ := newManaged("allow", "tcp", "80", "any", "test")
	base := window{ID: r.ID, Rule: r, Kind: "daily", Clock: "03:00", Zone: "Europe/Moscow", Seconds: 3600}
	for _, mutate := range []func(*window){func(w *window) { w.Seconds = 0 }, func(w *window) { w.Seconds = 86400 }, func(w *window) { w.Clock = "24:00" }, func(w *window) { w.Zone = "UTC\nExecStart=/bin/x" }, func(w *window) { w.Rule.Action = "deny" }, func(w *window) { w.Kind = "once"; w.Start = time.Time{} }} {
		w := base
		mutate(&w)
		if e := w.validate(); e == nil {
			t.Fatalf("accepted %+v", w)
		}
	}
}
func TestOverlappingWindowsKeepPermissionUntilLastEnd(t *testing.T) {
	m := managerFixture(t)
	r1, _ := newManaged("allow", "tcp", "80", "any", "one")
	r2, _ := newManaged("allow", "tcp", "80", "any", "two")
	w1 := window{ID: r1.ID, Rule: r1, Kind: "lease", Start: m.now(), Seconds: 1800}
	w2 := window{ID: r2.ID, Rule: r2, Kind: "lease", Start: m.now(), Seconds: 3600}
	writeJSON(m.path("windows.json"), []window{w1, w2})
	c, _ := m.config()
	desired, e := m.desired(c)
	if e != nil || len(desired) != 1 || !desired[0].Until.Equal(w2.Start.Add(time.Hour)) {
		t.Fatal(desired, e)
	}
	m.now = func() time.Time { return w1.Start.Add(31 * time.Minute) }
	desired, e = m.desired(c)
	if e != nil || len(desired) != 1 {
		t.Fatal(desired, e)
	}
	c.Rules = []managedRule{r1}
	desired, e = m.desired(c)
	if e != nil || len(desired) != 1 || desired[0].Temporary {
		t.Fatal("permanent rule was turned into a lease", desired, e)
	}
}
func TestManagerTransactionNewSSHAndWorkerRollback(t *testing.T) {
	m := managerFixture(t)
	before, _ := m.config()
	after := before
	r, _ := newManaged("allow", "tcp", "443", "any", "Web")
	after.Rules = []managedRule{r}
	p, e := m.change("add", after)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.confirm(p.Token); e == nil {
		t.Fatal("same SSH accepted")
	}
	if _, e = m.change("another", before); e == nil {
		t.Fatal("parallel mutation")
	}
	m.now = func() time.Time { return p.Deadline }
	if e = m.worker(false); e != nil {
		t.Fatal(e)
	}
	c, _ := m.config()
	if len(c.Rules) != 0 {
		t.Fatal("worker did not restore base config")
	}
}
func TestManagerTimerFailureDoesNotPublishAfterConfig(t *testing.T) {
	m := managerFixture(t)
	m.run = func(name string, args ...string) (string, error) {
		if name == "systemd-run" {
			return "", errors.New("timer failed")
		}
		return "enabled", nil
	}
	c, _ := m.config()
	c.Policy = "allow"
	if _, e := m.change("policy", c); e == nil {
		t.Fatal("expected failure")
	}
	actual, _ := m.config()
	if actual.Policy != "deny" {
		t.Fatal("unsafe config committed")
	}
	if p, e := m.pending(); e != nil || p != nil {
		t.Fatal(p, e)
	}
}
func TestManagerConfirmedChangesSurviveLateCallback(t *testing.T) {
	m := managerFixture(t)
	c, _ := m.config()
	c.Policy = "allow"
	p, e := m.change("policy", c)
	if e != nil {
		t.Fatal(e)
	}
	m.ssh = "192.0.2.1 2000 192.0.2.2 22"
	if e = m.confirm(p.Token); e != nil {
		t.Fatal(e)
	}
	if e = m.rollback(); e != nil {
		t.Fatal(e)
	}
	actual, _ := m.config()
	if actual.Policy != "allow" {
		t.Fatal("late callback undid confirmed config")
	}
}
func TestCertbotPrePostAndCrashExpiry(t *testing.T) {
	m := managerFixture(t)
	if e := m.certbotOpen(); e != nil {
		t.Fatal(e)
	}
	windows, _ := m.windows()
	if len(windows) != 1 || windows[0].Seconds != 3600 || windows[0].Rule.Port != "80" {
		t.Fatal(windows)
	}
	if e := m.certbotOpen(); e != nil {
		t.Fatal(e)
	}
	windows, _ = m.windows()
	if len(windows) != 1 {
		t.Fatal("duplicate lease")
	}
	c, _ := m.config()
	m.now = func() time.Time { return windows[0].Start.Add(time.Hour) }
	desired, e := m.desired(c)
	if e != nil || len(desired) != 0 {
		t.Fatal("expired certbot grant retained", desired, e)
	}
	if e = m.certbotClose(); e != nil {
		t.Fatal(e)
	}
	windows, _ = m.windows()
	if len(windows) != 0 {
		t.Fatal("post hook retained lease")
	}
}
func TestCertbotHooksTimerAndRemovalAreScoped(t *testing.T) {
	m := managerFixture(t)
	if e := m.installCertbotHooks(); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"pre", "post"} {
		b, e := os.ReadFile(filepath.Join(m.system, "letsencrypt", "renewal-hooks", kind, "50-vpswall"))
		if e != nil || strings.Contains(string(b), "\r") {
			t.Fatal(string(b), e)
		}
	}
	if e := m.certbotTimer("03:15", "Europe/Moscow"); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(m.system, "systemd", "system", "vpswall-certbot.timer"))
	if !strings.Contains(string(b), "03:15:00 Europe/Moscow") {
		t.Fatal(string(b))
	}
	foreign := filepath.Join(m.system, "letsencrypt", "renewal-hooks", "pre", "10-foreign")
	os.WriteFile(foreign, []byte("foreign"), 0755)
	if e := m.removeCertbotIntegration(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(foreign); e != nil {
		t.Fatal("foreign hook removed")
	}
}
func TestBackendGeneratorsKeepNamespacesAndPriority(t *testing.T) {
	permanent, _ := newManaged("deny", "tcp", "80", "any", "deny")
	temporary, _ := newManaged("allow", "tcp", "80", "any", "lease")
	temporary.Temporary = true
	temporary.Until = time.Now().Add(time.Hour)
	c := managerConfig{Backend: "nftables", Enabled: true, Zone: "public", Policy: "deny"}
	script := nftScript(c, []managedRule{permanent, temporary}, true)
	if strings.Contains(script, "flush ruleset") || !strings.Contains(script, "delete table inet vpswall") || strings.Index(script, "VPSWall:"+temporary.ID) > strings.Index(script, "VPSWall:"+permanent.ID) {
		t.Fatal(script)
	}
	for _, ipv6 := range []bool{false, true} {
		script := iptScript(c, []managedRule{permanent, temporary}, ipv6)
		if strings.Contains(script, "-F INPUT") || strings.Contains(script, "-P INPUT") {
			t.Fatal(script)
		}
	}
	first := richRule(permanent, 0)
	if first != richRule(permanent, 99) {
		t.Fatal("ownership depends on array index")
	}
	if !strings.Contains(first, `priority="-15000"`) {
		t.Fatal(first)
	}
	if foreignNFTInput(`{"nftables":[{"chain":{"table":"vpswall","hook":"input"}}]}`) {
		t.Fatal("own chain rejected")
	}
	if !foreignNFTInput(`{"nftables":[{"chain":{"table":"foreign","hook":"input"}}]}`) {
		t.Fatal("foreign chain accepted")
	}
}
func TestForeignRichRuleCollisionDoesNotEnterOwnershipJournal(t *testing.T) {
	m := managerFixture(t)
	m.demo = false
	m.run = func(name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if name == "ufw" {
			return "Status: inactive", nil
		}
		if strings.Contains(joined, "--state") {
			return "running", nil
		}
		if strings.Contains(joined, "--query-rich-rule") {
			return "yes", nil
		}
		return "", nil
	}
	c := managerConfig{Backend: "firewalld", Enabled: true, Zone: "public", Policy: "allow"}
	r, _ := newManaged("allow", "tcp", "80", "any", "x")
	c.Rules = []managedRule{r}
	if e := m.synchronize(c, true); e == nil {
		t.Fatal("foreign rule adopted")
	}
	if _, e := os.Stat(m.path("owned.json")); !os.IsNotExist(e) {
		t.Fatal("foreign rule entered journal")
	}
}
func TestTUIKeyboardFormsAndReviewDefaultToCancel(t *testing.T) {
	m := managerFixture(t)
	u := newUI(m)
	next, _ := u.Update(tea.KeyMsg{Type: tea.KeyEnter})
	u = next.(uiModel)
	if u.screen != "rules" {
		t.Fatal(u.screen)
	}
	next, _ = u.Update(tea.KeyMsg{Type: tea.KeyEnter})
	u = next.(uiModel)
	if u.screen != "form" {
		t.Fatal(u.screen)
	}
	next, _ = u.Update(tea.KeyMsg{Type: tea.KeyRight})
	u = next.(uiModel)
	if u.fields[0].input.Value() != "запретить" {
		t.Fatal("enum keyboard")
	}
	for i := 0; i <= len(u.fields); i++ {
		next, _ = u.Update(tea.KeyMsg{Type: tea.KeyEnter})
		u = next.(uiModel)
	}
	if u.screen != "review" || u.cursor != 1 {
		t.Fatal("review did not default to cancel", u.screen, u.cursor)
	}
	view := ansi.Strip(u.View())
	if !strings.Contains(view, "╭") || !strings.Contains(view, "Отмена") {
		t.Fatal(view)
	}
}
func TestTUINarrowAndWideScreens(t *testing.T) {
	u := newUI(managerFixture(t))
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 120, Height: 40}} {
		updated, _ := u.Update(size)
		u = updated.(uiModel)
		for _, line := range strings.Split(ansi.Strip(u.View()), "\n") {
			if ansi.StringWidth(line) > size.Width {
				t.Fatalf("line wider than %d: %s", size.Width, line)
			}
		}
	}
}

func TestInstallerMasksNewServiceAndDoesNotActivateIt(t *testing.T) {
	m := managerFixture(t)
	m.demo = false
	installed := false
	var calls []string
	m.lookup = func(name string) (string, error) {
		if name == "apt-get" || name == "firewall-cmd" && installed {
			return "/fake/" + name, nil
		}
		return "", errors.New("missing")
	}
	m.run = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "apt-get" && args[0] == "install" {
			installed = true
		}
		if name == "systemctl" && args[0] == "is-enabled" {
			return "disabled", nil
		}
		return "", nil
	}
	if e := m.installBackend("firewalld"); e != nil {
		t.Fatal(e)
	}
	all := strings.Join(calls, "\n")
	if !strings.Contains(all, "mask --runtime firewalld.service") || !strings.Contains(all, "disable firewalld.service") || !strings.Contains(all, "unmask --runtime firewalld.service") {
		t.Fatal(all)
	}
	if strings.Contains(all, "systemctl start") || strings.Contains(all, "systemctl enable") {
		t.Fatal("installation activated the firewall", all)
	}
}
func TestInstallerFailureStillUnmasksItsService(t *testing.T) {
	m := managerFixture(t)
	m.demo = false
	var calls []string
	m.lookup = func(name string) (string, error) {
		if name == "dnf" {
			return "/fake/dnf", nil
		}
		return "", errors.New("missing")
	}
	m.run = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "dnf" {
			return "", errors.New("package unavailable")
		}
		return "disabled", nil
	}
	if e := m.installBackend("firewalld"); e == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(strings.Join(calls, "\n"), "unmask --runtime firewalld.service") {
		t.Fatal(calls)
	}
}
func TestCheckReadyRequiresRunningScheduler(t *testing.T) {
	m := managerFixture(t)
	m.demo = false
	m.run = func(name string, args ...string) (string, error) {
		if args[0] == "is-active" {
			return "inactive", errors.New("inactive")
		}
		return "enabled", nil
	}
	if e := m.checkReady(); e == nil {
		t.Fatal("lease allowed without running scheduler")
	}
}
func TestTUIFormAndReviewFitStandardTerminal(t *testing.T) {
	u := newUI(managerFixture(t))
	model, _ := u.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	u = model.(uiModel)
	u.ruleForm("")
	check := func() {
		view := ansi.Strip(u.View())
		if len(strings.Split(view, "\n")) > 24 {
			t.Fatal("vertical overflow", view)
		}
		for _, line := range strings.Split(view, "\n") {
			if ansi.StringWidth(line) > 80 {
				t.Fatal("horizontal overflow", line)
			}
		}
	}
	check()
	u.review("Продолжить?", strings.Repeat("Подробное описание изменения и условий применения.\n", 20), "home", func() (string, error) { return "ok", nil })
	check()
}
