package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHChoiceDefaultsToKeepAndDoesNotChangeService(t *testing.T) {
	m := managerFixture(t)
	c, _ := m.config()
	c.Enabled = false
	writeJSON(m.path("manager.json"), c)
	u := newUI(m)
	u.open("settings")
	u.activate()
	if u.screen != "ssh-choice" || u.cursor != 0 || u.items[0].key != "ssh-keep" {
		t.Fatal("no explicit safe default", u.screen)
	}
	u.activate()
	if u.screen != "review" || !strings.Contains(u.reviewText, "22 открытым") {
		t.Fatal(u.reviewText)
	}
	if _, e := u.reviewAction(); e != nil {
		t.Fatal(e)
	}
	c, _ = m.config()
	if !c.Enabled || len(c.Rules) != 1 || c.Rules[0].Port != "22" {
		t.Fatal(c)
	}
	if _, e := os.Stat(m.sshUnitPath("2222")); !os.IsNotExist(e) {
		t.Fatal("default changed SSH")
	}
}

func sshAfter(t *testing.T, m *manager, port string) managerConfig {
	t.Helper()
	c, _ := m.config()
	c, e := keepSSH(c, m.ssh)
	if e != nil {
		t.Fatal(e)
	}
	r, e := newManaged("allow", "tcp", port, "192.0.2.1", "SSH")
	if e != nil {
		t.Fatal(e)
	}
	r.Priority = 0
	r.AutoSSH = true
	c.Rules = append(c.Rules, r)
	return c
}
func TestSSHMigrationRollbackAndNewPortConfirmation(t *testing.T) {
	for _, confirm := range []bool{false, true} {
		m := managerFixture(t)
		p, e := m.changeSSH("SSH", sshAfter(t, m, "2222"), "2222")
		if e != nil {
			t.Fatal(e)
		}
		unit, e := os.ReadFile(m.sshUnitPath("2222"))
		if e != nil || !strings.Contains(string(unit), "-p 2222") {
			t.Fatal(string(unit), e)
		}
		c, _ := m.config()
		if len(c.Rules) != 2 || c.Rules[0].Port != "22" {
			t.Fatal("old port lost", c)
		}
		m.ssh = "192.0.2.1 2000 192.0.2.2 22"
		if e = m.confirm(p.Token); e == nil {
			t.Fatal("old port confirmation accepted")
		}
		if confirm {
			m.ssh = "192.0.2.1 3000 192.0.2.2 2222"
			if e = m.confirm(p.Token); e != nil {
				t.Fatal(e)
			}
			if e = m.rollback(); e != nil {
				t.Fatal(e)
			}
			if _, e = os.Stat(m.sshUnitPath("2222")); e != nil {
				t.Fatal("confirmed listener removed")
			}
		} else {
			if e = m.rollback(); e != nil {
				t.Fatal(e)
			}
			if _, e = os.Stat(m.sshUnitPath("2222")); !os.IsNotExist(e) {
				t.Fatal("listener retained on rollback")
			}
			c, _ = m.config()
			if len(c.Rules) != 0 {
				t.Fatal("new rules retained")
			}
		}
	}
}
func TestSSHMigrationFailureAndForeignUnitPreservation(t *testing.T) {
	m := managerFixture(t)
	os.MkdirAll(filepath.Dir(m.sshUnitPath("2222")), 0755)
	os.WriteFile(m.sshUnitPath("2222"), []byte("foreign"), 0644)
	if _, e := m.changeSSH("SSH", sshAfter(t, m, "2222"), "2222"); e == nil {
		t.Fatal("foreign overwritten")
	}
	os.Remove(m.sshUnitPath("2222"))
	base := m.run
	m.run = func(name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "enable" {
			return "", errors.New("start failed")
		}
		return base(name, args...)
	}
	if _, e := m.changeSSH("SSH", sshAfter(t, m, "2222"), "2222"); e == nil {
		t.Fatal("failure ignored")
	}
	if _, e := os.Stat(m.sshUnitPath("2222")); !os.IsNotExist(e) {
		t.Fatal("failed listener retained")
	}
	if p, e := m.pending(); e != nil || p != nil {
		t.Fatal(p, e)
	}
	for _, port := range []string{"0", "65536", "22; echo bad", "../../file", "0022"} {
		if validateSSHPort(port) == nil {
			t.Fatal(port)
		}
	}
}
