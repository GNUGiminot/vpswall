package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseListenersBindings(t *testing.T) {
	output := "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=12,fd=3))\n" +
		"tcp LISTEN 0 128 [::]:443 [::]:*\n" +
		"udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n" +
		"tcp LISTEN 0 128 [::1]:8090 [::]:*\n" +
		"udp UNCONN 0 0 [fe80::1%eth0]:5353 [::]:*\n" +
		"tcp LISTEN 0 128 *:8080 *:*\n" +
		"tcp LISTEN 0 128 [::ffff:127.0.0.1]:9000 [::]:*\n"
	got, err := parseListeners(output)
	if err != nil || len(got) != 7 {
		t.Fatal(got, err)
	}
	for i, want := range []string{"all", "all", "loopback", "loopback", "address", "all", "loopback"} {
		if got[i].Scope != want {
			t.Fatalf("%d: %+v", i, got[i])
		}
	}
	if got[0].Port != "22" || !strings.Contains(got[0].Process, "sshd") || got[4].Address != "fe80::1%eth0" {
		t.Fatal(got)
	}
	for _, bad := range []string{"unexpected data", "tcp LISTEN 0 128 broken *:*", "tcp LISTEN 0 128 [::]:x *:*", "tcp LISTEN 0 128 *:65536 *:*"} {
		if _, err := parseListeners(bad); err == nil {
			t.Fatal("silently accepted malformed ss output", bad)
		}
	}
}

func TestInventoryReadsConsoleRulesBeforeConfigurationWithoutMutations(t *testing.T) {
	m := managerFixture(t)
	os.Remove(m.path("manager.json"))
	m.demo = false
	m.lookup = func(name string) (string, error) { return "/synthetic/" + name, nil }
	var mu sync.Mutex
	calls := []string{}
	m.run = func(name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		mu.Lock()
		calls = append(calls, command)
		mu.Unlock()
		switch command {
		case "ss -H -lntup":
			return "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*", nil
		case "ufw status numbered":
			return "Status: active\n[ 1] 8080/tcp ALLOW IN Anywhere # Console service", nil
		case "ufw show added":
			return "ufw allow 8080/tcp", nil
		case "ufw status verbose":
			return "Status: active\nDefault: deny (incoming)", nil
		case "nft -a list ruleset":
			return "table ip nat { chain PREROUTING { tcp dport 8443 dnat to 192.0.2.10:443 } }", nil
		case "firewall-cmd --list-all-zones":
			return "work (active)\n services: ssh http\n ports: 9090/tcp", nil
		case "firewall-cmd --permanent --list-all-zones":
			return "public\n ports: 9091/tcp", nil
		case "firewall-cmd --direct --get-all-rules":
			return "ipv4 filter INPUT 0 -p tcp --dport 9000 -j ACCEPT", nil
		case "firewall-offline-cmd --list-all-zones":
			return "public\n ports: 9091/tcp", nil
		case "iptables-save ":
			return "*nat\n-A PREROUTING -p udp --dport 40000 -j DNAT --to-destination 192.0.2.10:40000\nCOMMIT", nil
		case "ip6tables-save ":
			return "*filter\n-A INPUT -p tcp --dport 443 -j ACCEPT\nCOMMIT", nil
		default:
			t.Errorf("unexpected or mutating command: %s", command)
			return "", errors.New("unexpected command")
		}
	}
	inv := m.inventory()
	if len(inv.Errors) != 0 || len(inv.Listeners) != 1 || len(inv.Firewalls) != 10 {
		t.Fatal(inv)
	}
	for _, needle := range []string{"8080/tcp", "9090/tcp", "9091/tcp", "dnat to", "--dport 40000", "ip6tables-save", "--dport 9000"} {
		if !strings.Contains(inv.text(), needle) {
			t.Fatal("missing console rules:", needle, inv.text())
		}
	}
	if _, err := os.Stat(m.path("manager.json")); !os.IsNotExist(err) {
		t.Fatal("inventory wrote configuration", err)
	}
	c, err := m.config()
	if err != nil || c.Backend != "" || c.Enabled || len(c.Rules) != 0 {
		t.Fatal(c, err)
	}
}

func TestInventoryReportsPartialErrorsAndLimitsOutput(t *testing.T) {
	m := managerFixture(t)
	m.run = func(name string, args ...string) (string, error) {
		if name == "ss" {
			return "", errors.New("ss unavailable")
		}
		if len(args) > 0 && args[0] == "show" {
			return "", errors.New("cannot read UFW")
		}
		return strings.Repeat("x", 300000), nil
	}
	inv := m.inventory()
	if len(inv.Errors) != 1 || len(inv.Listeners) != 0 || len(inv.Firewalls) != 3 {
		t.Fatal(inv)
	}
	if !inv.Firewalls[0].Truncated || len(inv.Firewalls[0].Output) != 262144 || inv.Firewalls[1].Error == "" {
		t.Fatal("partial failure hidden")
	}
	if !strings.Contains(inv.text(), "Ошибка чтения") {
		t.Fatal(inv.text())
	}
}

func TestWebInventoryIsAuthenticatedCachedAndRefreshes(t *testing.T) {
	s, token := webFixture(t)
	var mu sync.Mutex
	calls := 0
	native := "8080/tcp ALLOW IN Anywhere"
	s.m.run = func(name string, args ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if name == "ss" {
			return "", nil
		}
		return native, nil
	}
	get := func() webState {
		t.Helper()
		w := webRequest(s, token, "GET", "/api/state", "", "", "127.0.0.1:8090")
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var state webState
		if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	if w := webRequest(s, "bad", http.MethodGet, "/api/state", "", "", "127.0.0.1:8090"); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if calls != 0 {
		t.Fatal("read native rules before auth")
	}
	first := get()
	if !strings.Contains(first.Inventory.text(), "8080/tcp") {
		t.Fatal(first.Inventory)
	}
	mu.Lock()
	n := calls
	native = "9090/tcp ALLOW IN Anywhere"
	mu.Unlock()
	get()
	mu.Lock()
	if calls != n {
		t.Error("cache not reused", calls, n)
	}
	mu.Unlock()
	s.inventoryCachedAt = time.Now().Add(-11 * time.Second)
	next := get()
	if !strings.Contains(next.Inventory.text(), "9090/tcp") {
		t.Fatal("external changes hidden", next.Inventory)
	}
}

func TestInventoryDoesNotBlockMutationLock(t *testing.T) {
	s, _ := webFixture(t)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	s.m.run = func(name string, args ...string) (string, error) {
		if name == "ss" {
			entered <- struct{}{}
			<-release
		}
		return "", nil
	}
	done := make(chan struct{})
	go func() { s.systemInventory(); close(done) }()
	<-entered
	lockDone := make(chan error, 1)
	go func() { lockDone <- s.m.withLock(func() error { return nil }) }()
	select {
	case err := <-lockDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("native read blocks firewall changes")
	}
	close(release)
	<-done
}

func TestForwardFailureRestoresSavedConfiguration(t *testing.T) {
	m := managerFixture(t)
	fail := true
	m.run = func(name string, args ...string) (string, error) {
		if name == "iptables" && fail && strings.Contains(strings.Join(args, " "), "-A RELAY-PRE") {
			fail = false
			return "", errors.New("synthetic kernel failure")
		}
		return "", nil
	}
	err := m.addForward(portForward{Protocol: "udp", ListenPort: "40000", Target: "192.0.2.10"})
	if err == nil {
		t.Fatal("apply failure ignored")
	}
	list, e := m.forwards()
	if e != nil || len(list) != 0 {
		t.Fatal("failed forwarding left on disk", list, e)
	}
	history, _ := os.ReadFile(m.path("history.log"))
	if strings.Contains(string(history), "FORWARD ADD") {
		t.Fatal("logged failed forward as success")
	}
}

func TestForwardRefusesWhenSocketCheckFails(t *testing.T) {
	m := managerFixture(t)
	m.demo = false
	m.run = func(name string, args ...string) (string, error) {
		if name == "ss" {
			return "", fmt.Errorf("ss failed")
		}
		t.Error("unexpected mutation", name, args)
		return "", nil
	}
	if err := m.addForward(portForward{Protocol: "udp", ListenPort: "40000", Target: "192.0.2.10"}); err == nil {
		t.Fatal("failed socket check accepted")
	}
	if len(binaryPaths["sysctl"]) == 0 {
		t.Fatal("forwarding sysctl missing from command allowlist")
	}
}

func TestUFWNativeRulesPreserveConditions(t *testing.T) {
	output := "Status: active\n[ 1] 8080/tcp                   ALLOW IN    Anywhere # Console service\n" +
		"[ 2] 443/tcp (v6)               ALLOW IN    Anywhere (v6)\n" +
		"[ 3] OpenSSH on eth0            LIMIT IN    192.0.2.0/24\n" +
		"[ 4] 53/udp                     DENY OUT    Anywhere\n" +
		"[ 5] 8000:8010/tcp              REJECT FWD  198.51.100.0/24\n"
	got := parseUFWNumbered(output)
	if len(got) != 5 || got[0].Comment != "Console service" || got[1].Destination != "443/tcp (v6)" || got[2].Destination != "OpenSSH on eth0" || got[2].Action != "limit" || got[3].Direction != "OUT" || got[4].Direction != "FWD" {
		t.Fatal(got)
	}
}
