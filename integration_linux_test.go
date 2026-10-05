package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Live tests are strictly opt-in and require both a private root and a separate netns.
func requireLab(t *testing.T) {
	t.Helper()
	if os.Getenv("VPSWALL_LAB") != "1" {
		t.Skip("isolated Linux lab only")
	}
	if _, e := os.Stat("/VPSWALL_ISOLATED_ROOT"); e != nil {
		t.Fatal("private root marker missing")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	init, _ := os.Readlink("/proc/1/ns/net")
	if self == "" || self == init {
		t.Fatal("test must run in a separate network namespace")
	}
}
func liveManager(t *testing.T, b string) *manager {
	t.Helper()
	root := t.TempDir()
	m := &manager{root: root, system: "/etc", runtimeDir: filepath.Join(root, "run"), now: time.Now, ssh: "192.0.2.1 1000 192.0.2.2 22"}
	m.run = managerCommand
	c := managerConfig{Backend: b, Zone: "public", Enabled: true, Policy: "deny"}
	if e := writeJSON(m.path("manager.json"), c); e != nil {
		t.Fatal(e)
	}
	return m
}
func resetKernel(t *testing.T) {
	t.Helper()
	if _, e := managerCommand("nft", "flush", "ruleset"); e != nil {
		t.Fatal(e)
	}
}
func peerNetwork(t *testing.T) {
	t.Helper()
	ip := "/usr/sbin/ip"
	if _, e := os.Stat(ip); e != nil {
		ip = "/usr/bin/ip"
	}
	run := func(args ...string) {
		t.Helper()
		if out, e := exec.Command(ip, args...).CombinedOutput(); e != nil {
			t.Fatalf("ip %v: %v %s", args, e, out)
		}
	}
	run("netns", "add", "vpswall-client")
	t.Cleanup(func() {
		exec.Command(ip, "netns", "delete", "vpswall-client").Run()
		exec.Command(ip, "link", "delete", "vpswall-host").Run()
	})
	run("link", "add", "vpswall-host", "type", "veth", "peer", "name", "vpswall-peer")
	run("link", "set", "vpswall-peer", "netns", "vpswall-client")
	run("addr", "add", "192.0.2.1/24", "dev", "vpswall-host")
	run("link", "set", "vpswall-host", "up")
	run("netns", "exec", "vpswall-client", ip, "addr", "add", "192.0.2.2/24", "dev", "vpswall-peer")
	run("netns", "exec", "vpswall-client", ip, "link", "set", "vpswall-peer", "up")
	for _, port := range []string{"80", "8080"} {
		listener, e := net.Listen("tcp", "0.0.0.0:"+port)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				c, e := listener.Accept()
				if e != nil {
					return
				}
				c.Close()
			}
		}()
	}
}
func probePort(t *testing.T, port string, open bool) {
	t.Helper()
	ip := "/usr/sbin/ip"
	if _, e := os.Stat(ip); e != nil {
		ip = "/usr/bin/ip"
	}
	expect := "closed"
	if open {
		expect = "open"
	}
	cmd := exec.Command(ip, "netns", "exec", "vpswall-client", "/tmp/vpswall-linux.test", "-test.run", "^TestIntegrationProbe$", "-test.timeout", "5s")
	cmd.Env = append(os.Environ(), "VPSWALL_PROBE_PORT="+port, "VPSWALL_PROBE_EXPECT="+expect)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("port %s should be %s: %v\n%s", port, expect, e, out)
	}
}
func TestIntegrationProbe(t *testing.T) {
	port := os.Getenv("VPSWALL_PROBE_PORT")
	if port == "" {
		t.Skip("probe process only")
	}
	requireLab(t)
	if port != "80" && port != "8080" {
		t.Fatal("invalid probe port")
	}
	connection, e := net.DialTimeout("tcp", "192.0.2.1:"+port, 1500*time.Millisecond)
	if e == nil {
		connection.Close()
	}
	if (e == nil) != (os.Getenv("VPSWALL_PROBE_EXPECT") == "open") {
		t.Fatal("unexpected TCP connectivity", e)
	}
}
func mustRun(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, e := managerCommand(name, args...)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestIntegrationNFTAndIPTables(t *testing.T) {
	requireLab(t)
	for _, backend := range []string{"nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			resetKernel(t)
			peerNetwork(t)
			m := liveManager(t, backend)
			c, _ := m.config()
			r, _ := newManaged("allow", "tcp", "8080", "192.0.2.0/24", "test")
			c.Rules = []managedRule{r}
			if e := m.synchronize(c, true); e != nil {
				t.Fatal(e)
			}
			check := func(port string) bool {
				if backend == "nftables" {
					out := mustRun(t, "nft", "list", "table", "inet", "vpswall")
					return strings.Contains(out, "dport "+port+" ")
				}
				out := mustRun(t, "iptables", "-S", "VPSWALL_IN")
				return strings.Contains(out, "--dport "+port+" ")
			}
			if !check("8080") {
				t.Fatal("permanent rule missing")
			}
			probePort(t, "8080", true)
			probePort(t, "80", false)
			lease, _ := newManaged("allow", "tcp", "80", "any", "temporary")
			w := window{ID: lease.ID, Rule: lease, Kind: "lease", Start: m.now(), Seconds: 60}
			writeJSON(m.path("windows.json"), []window{w})
			if e := m.synchronize(c, true); e != nil {
				t.Fatal(e)
			}
			if !check("80") {
				t.Fatal("lease missing")
			}
			probePort(t, "80", true)
			m.now = func() time.Time { return w.Start.Add(61 * time.Second) }
			if e := m.synchronize(c, true); e != nil {
				t.Fatal(e)
			}
			if check("80") || !check("8080") {
				t.Fatal("expiry removed permanent permission or kept lease")
			}
			probePort(t, "80", false)
			probePort(t, "8080", true)
			c.Enabled = false
			if e := m.synchronize(c, true); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestIntegrationUFW(t *testing.T) {
	requireLab(t)
	resetKernel(t)
	peerNetwork(t)
	mustRun(t, "ufw", "--force", "reset")
	m := liveManager(t, "ufw")
	c, _ := m.config()
	// This rule belongs to the system administrator, not to VPSWall.
	mustRun(t, "ufw", "allow", "443/tcp", "comment", "foreign-admin")
	r, _ := newManaged("allow", "tcp", "8080", "192.0.2.0/24", "test")
	c.Rules = []managedRule{r}
	if e := m.synchronize(c, true); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(mustRun(t, "ufw", "show", "added"), "VPSWall:"+r.ID) {
		t.Fatal("owned rule missing")
	}
	probePort(t, "8080", true)
	probePort(t, "80", false)
	lease, _ := newManaged("allow", "tcp", "80", "any", "lease")
	w := window{ID: lease.ID, Rule: lease, Kind: "lease", Start: m.now(), Seconds: 60}
	writeJSON(m.path("windows.json"), []window{w})
	if e := m.synchronize(c, true); e != nil {
		t.Fatal(e)
	}
	probePort(t, "80", true)
	m.now = func() time.Time { return w.Start.Add(61 * time.Second) }
	if e := m.synchronize(c, true); e != nil {
		t.Fatal(e)
	}
	out := mustRun(t, "ufw", "show", "added")
	if strings.Contains(out, "VPSWall:"+lease.ID) || !strings.Contains(out, "foreign-admin") {
		t.Fatal(out)
	}
	probePort(t, "80", false)
	probePort(t, "8080", true)
	// A duplicate foreign permission must not be relabelled and then deleted on expiry.
	duplicate, _ := newManaged("allow", "tcp", "443", "any", "duplicate")
	c.Rules = append(c.Rules, duplicate)
	if e := m.synchronize(c, true); e == nil {
		t.Fatal("foreign duplicate was adopted")
	}
	out = mustRun(t, "ufw", "show", "added")
	if !strings.Contains(out, "foreign-admin") {
		t.Fatal("foreign rule was modified")
	}
	c.Rules = []managedRule{r}
	c.Enabled = false
	if e := m.synchronize(c, true); e != nil {
		t.Fatal(e)
	}
}
func TestIntegrationFirewalld(t *testing.T) {
	requireLab(t)
	resetKernel(t)
	peerNetwork(t)
	os.MkdirAll("/run/dbus", 0755)
	os.Remove("/run/dbus/pid")
	os.Remove("/run/dbus/system_bus_socket")
	dbus := exec.Command("/usr/bin/dbus-daemon", "--system", "--nofork", "--nopidfile")
	if e := dbus.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { dbus.Process.Kill(); dbus.Wait() }()
	for i := 0; i < 50; i++ {
		if _, e := os.Stat("/run/dbus/system_bus_socket"); e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	var daemon *exec.Cmd
	start := func() error {
		path, e := binary("firewall-cmd")
		if e != nil {
			return e
		}
		_ = path
		daemon = exec.Command("/usr/sbin/firewalld", "--nofork", "--nopid", "--debug=2")
		log, e := os.OpenFile("/tmp/firewalld-lab.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if e != nil {
			return e
		}
		daemon.Stdout = log
		daemon.Stderr = log
		defer log.Close()
		if e = daemon.Start(); e != nil {
			return e
		}
		for i := 0; i < 100; i++ {
			if out, e := managerCommand("firewall-cmd", "--state"); e == nil && strings.TrimSpace(out) == "running" {
				return nil
			}
			if b, _ := os.ReadFile("/var/log/firewalld"); strings.Contains(string(b), "Raising SystemExit") {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		b, _ := os.ReadFile("/tmp/firewalld-lab.log")
		extra, _ := os.ReadFile("/var/log/firewalld")
		state, stateErr := managerCommand("firewall-cmd", "--state")
		os.WriteFile("/opt/vpswall/tests/linux-lab-firewalld.log", append(b, extra...), 0600)
		var details []string
		for _, line := range strings.Split(string(extra), "\n") {
			if strings.Contains(line, "ERROR:") || strings.Contains(line, "Error:") {
				if len(line) > 600 {
					line = line[:600]
				}
				details = append(details, line)
				if len(details) >= 12 {
					break
				}
			}
		}
		return fmt.Errorf("firewalld start: %s\nstate=%s error=%v", strings.Join(details, "\n"), state, stateErr)
	}
	stop := func() {
		if daemon != nil {
			daemon.Process.Signal(os.Interrupt)
			daemon.Wait()
			daemon = nil
		}
	}
	defer stop()
	m := liveManager(t, "firewalld")
	m.run = func(name string, args ...string) (string, error) {
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "start" {
				return "", start()
			}
			if len(args) > 0 && args[0] == "stop" {
				stop()
				return "", nil
			}
			return "", errors.New("unsupported systemctl in lab")
		}
		return managerCommand(name, args...)
	}
	c, _ := m.config()
	r, _ := newManaged("allow", "tcp", "8080", "192.0.2.0/24", "test")
	c.Rules = []managedRule{r}
	if e := m.synchronize(c, true); e != nil {
		t.Fatal(e)
	}
	probePort(t, "8080", true)
	probePort(t, "80", false)
	foreign := `rule priority="-25000" port port="443" protocol="tcp" accept`
	mustRun(t, "firewall-cmd", "--zone=public", "--add-rich-rule="+foreign)
	lease, _ := newManaged("allow", "tcp", "80", "any", "lease")
	w := window{ID: lease.ID, Rule: lease, Kind: "lease", Start: m.now(), Seconds: 60}
	writeJSON(m.path("windows.json"), []window{w})
	if e := m.synchronize(c, true); e != nil {
		t.Fatal(e)
	}
	out := mustRun(t, "firewall-cmd", "--zone=public", "--list-rich-rules")
	if !strings.Contains(out, `port="80"`) {
		t.Fatal(out)
	}
	probePort(t, "80", true)
	m.now = func() time.Time { return w.Start.Add(61 * time.Second) }
	if e := m.synchronize(c, true); e != nil {
		t.Fatal(e)
	}
	out = mustRun(t, "firewall-cmd", "--zone=public", "--list-rich-rules")
	if strings.Contains(out, `port="80"`) || !strings.Contains(out, `port="443"`) {
		t.Fatal(out)
	}
	probePort(t, "80", false)
	probePort(t, "8080", true)
	c.Enabled = false
	if e := m.synchronize(c, true); e != nil {
		t.Fatal(e)
	}
}
func TestIntegrationCertbotUnitFiles(t *testing.T) {
	requireLab(t)
	m := liveManager(t, "ufw")
	m.demo = true
	if e := os.WriteFile("/usr/bin/certbot", []byte("#!/bin/sh\nexit 0\n"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := m.certbotTimer("03:00", "Europe/Moscow"); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command("/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/vpswall-certbot.service", "/etc/systemd/system/vpswall-certbot.timer").CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
}
