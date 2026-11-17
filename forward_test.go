package main

import (
	"os"
	"strings"
	"testing"
)

func TestForwardValidation(t *testing.T) {
	ok := portForward{"udp", "40000", "203.0.113.10", "40000"}
	if e := ok.validate(); e != nil {
		t.Fatal(e)
	}
	bad := []portForward{
		{"icmp", "1", "1.2.3.4", "1"},
		{"tcp", "0", "1.2.3.4", "1"},
		{"tcp", "70000", "1.2.3.4", "1"},
		{"tcp", "080", "1.2.3.4", "80"},
		{"tcp", "80", "127.0.0.1", "80"},
		{"tcp", "80", "::1", "80"},
		{"tcp", "80", "example.com", "80"},
		{"tcp", "80", "1.2.3.4; rm", "80"},
	}
	for _, f := range bad {
		if f.validate() == nil {
			t.Fatalf("accepted %+v", f)
		}
	}
}

func TestForwardConfCompatibleWithScript(t *testing.T) {
	list, e := parseForwards("# comment\n\nudp 40000 203.0.113.10 40000\ntcp 443 203.0.113.10 8443\n")
	if e != nil || len(list) != 2 || list[1].TargetPort != "8443" {
		t.Fatal(list, e)
	}
	if _, e = parseForwards("udp 1 2\n"); e == nil {
		t.Fatal("short line accepted")
	}
}

func TestForwardAddApplyDelete(t *testing.T) {
	m := managerFixture(t)
	var calls []string
	m.run = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	if e := m.addForward(portForward{Protocol: "udp", ListenPort: "40000", Target: "203.0.113.10"}); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(m.forwardConf())
	if !strings.Contains(string(b), "udp 40000 203.0.113.10 40000") {
		t.Fatal(string(b))
	}
	all := strings.Join(calls, "\n")
	for _, want := range []string{"net.ipv4.ip_forward=1", "-A RELAY-PRE -p udp --dport 40000 -j DNAT --to-destination 203.0.113.10:40000", "-A RELAY-POST -p udp -d 203.0.113.10 --dport 40000 -j MASQUERADE"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %q in\n%s", want, all)
		}
	}
	if e := m.addForward(portForward{Protocol: "udp", ListenPort: "40000", Target: "1.1.1.1"}); e == nil {
		t.Fatal("duplicate accepted")
	}
	if e := m.addForward(portForward{Protocol: "tcp", ListenPort: "22", Target: "1.1.1.1"}); e == nil {
		t.Fatal("current SSH port accepted")
	}
	calls = nil
	if e := m.removeForward("udp", "40000"); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(strings.Join(calls, "\n"), "DNAT") {
		t.Fatal("rule re-added after delete")
	}
	if e := m.removeForward("udp", "40000"); e == nil {
		t.Fatal("missing forward deleted")
	}
}
