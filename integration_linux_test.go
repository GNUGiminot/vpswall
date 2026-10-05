package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIntegrationWebAPI(t *testing.T) {
	requireLab(t)
	resetKernel(t)
	peerNetwork(t)
	m := liveManager(t, "nftables")
	base := m.run
	m.run = func(name string, args ...string) (string, error) {
		if name == "systemd-run" {
			return "", nil
		}
		if name == "systemctl" {
			if args[0] == "is-enabled" {
				return "enabled", nil
			}
			if args[0] == "is-active" {
				return "active", nil
			}
			return "", nil
		}
		return base(name, args...)
	}
	token, e := m.issueWebToken()
	if e != nil {
		t.Fatal(e)
	}
	panel := &webServer{m: m}
	server := httptest.NewServer(panel)
	defer server.Close()
	c, _ := m.config()
	action := webAction{Op: "rule-save", Revision: configRevision(c), Action: "allow", Protocol: "tcp", Port: "8080", Source: "any", Priority: 100, Comment: "HTTP API"}
	send := func(a webAction) webJob {
		t.Helper()
		data, _ := json.Marshal(a)
		req, _ := http.NewRequest("POST", server.URL+"/api/action", strings.NewReader(string(data)))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Origin", server.URL)
		req.Header.Set("Content-Type", "application/json")
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 202 {
			t.Fatal(res.StatusCode)
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			panel.mu.Lock()
			job := panel.job
			panel.mu.Unlock()
			if !job.Running {
				if job.Error != "" {
					t.Fatal(job.Error)
				}
				return job
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("web job timeout")
		return webJob{}
	}
	job := send(action)
	if job.Pending == nil {
		t.Fatal("no rollback transaction")
	}
	confirm := *m
	confirm.ssh = "192.0.2.1 2000 192.0.2.2 22"
	if e = confirm.confirm(job.Pending.Token); e != nil {
		t.Fatal(e)
	}
	probePort(t, "8080", true)
	probePort(t, "80", false)
	send(webAction{Op: "window-add", Protocol: "tcp", Port: "80", Source: "any", Kind: "lease", Duration: "1m"})
	probePort(t, "80", true)
	windows, _ := m.windows()
	if len(windows) != 1 {
		t.Fatal(windows)
	}
	send(webAction{Op: "window-delete", ID: windows[0].ID})
	probePort(t, "80", false)
	probePort(t, "8080", true)
	if e = m.webService(true); e != nil {
		t.Fatal(e)
	}
	unit := filepath.Join(m.system, "systemd", "system", "vpswall-web.service")
	if out, e := exec.Command("systemd-analyze", "verify", unit).CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	if e = m.webService(false); e != nil {
		t.Fatal(e)
	}
}

func TestIntegrationSSHMigration(t *testing.T) {
	requireLab(t)
	resetKernel(t)
	if out, e := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	root := t.TempDir()
	key := filepath.Join(root, "client")
	if out, e := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	if out, e := exec.Command("ssh-keygen", "-A").CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	os.MkdirAll("/run/sshd", 0755)
	config := "/etc/ssh/sshd_config"
	body := "HostKey /etc/ssh/ssh_host_ed25519_key\nAuthorizedKeysFile " + key + ".pub\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nStrictModes no\nUsePAM no\n"
	if e := os.WriteFile(config, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	processes := map[string]*exec.Cmd{}
	start := func(port string) error {
		cmd := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", config, "-p", port, "-o", "PidFile="+filepath.Join(root, "pid-"+port))
		log, e := os.Create(filepath.Join(root, "sshd-"+port+".log"))
		if e != nil {
			return e
		}
		defer log.Close()
		cmd.Stderr = log
		if e := cmd.Start(); e != nil {
			return e
		}
		processes[port] = cmd
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			c, e := net.DialTimeout("tcp", "127.0.0.1:"+port, 200*time.Millisecond)
			if e == nil {
				c.Close()
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		data, _ := os.ReadFile(log.Name())
		return fmt.Errorf("sshd did not listen: %s", data)
	}
	stop := func(port string) {
		if cmd := processes[port]; cmd != nil {
			cmd.Process.Kill()
			cmd.Wait()
			delete(processes, port)
		}
	}
	t.Cleanup(func() {
		for port := range processes {
			stop(port)
		}
	})
	if e := start("22"); e != nil {
		t.Fatal(e)
	}
	m := liveManager(t, "nftables")
	m.ssh = "127.0.0.1 1000 127.0.0.1 22"
	m.run = func(name string, args ...string) (string, error) {
		if name == "systemd-run" {
			return "", nil
		}
		if name == "systemctl" {
			if args[0] == "is-enabled" {
				return "enabled", nil
			}
			if args[0] == "is-active" {
				return "active", nil
			}
			if args[0] == "enable" {
				p := strings.TrimSuffix(strings.TrimPrefix(args[len(args)-1], "vpswall-ssh-"), ".service")
				return "", start(p)
			}
			if args[0] == "disable" {
				p := strings.TrimSuffix(strings.TrimPrefix(args[len(args)-1], "vpswall-ssh-"), ".service")
				stop(p)
			}
			return "", nil
		}
		return managerCommand(name, args...)
	}
	login := func(port string) string {
		t.Helper()
		out, e := exec.Command("ssh", "-F", "/dev/null", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-p", port, "root@127.0.0.1", "printf '%s' \"$SSH_CONNECTION\"").CombinedOutput()
		if e != nil {
			t.Fatal(e, string(out))
		}
		return string(out)
	}
	for i, confirm := range []bool{false, true} {
		port := strconv.Itoa(2222 + i)
		c, _ := m.config()
		c, e := keepSSH(c, m.ssh)
		if e != nil {
			t.Fatal(e)
		}
		r, _ := newManaged("allow", "tcp", port, "127.0.0.1", "SSH")
		r.Priority = 0
		c.Rules = append(c.Rules, r)
		p, e := m.changeSSH("SSH native test", c, port)
		if e != nil {
			t.Fatal(e)
		}
		if out, e := exec.Command("systemd-analyze", "verify", m.sshUnitPath(port)).CombinedOutput(); e != nil {
			t.Fatal(e, string(out))
		}
		actual := login(port)
		if !strings.HasSuffix(actual, " "+port) {
			t.Fatal(actual)
		}
		login("22") // original listener and key login remain available
		if confirm {
			m.ssh = actual
			if e = m.confirm(p.Token); e != nil {
				t.Fatal(e)
			}
			login(port)
		} else {
			m.ssh = login("22")
			if e = m.confirm(p.Token); e == nil {
				t.Fatal("old port accepted")
			}
			if e = m.rollback(); e != nil {
				t.Fatal(e)
			}
			if c, e := net.DialTimeout("tcp", "127.0.0.1:"+port, 300*time.Millisecond); e == nil {
				c.Close()
				t.Fatal("new listener retained")
			}
			login("22")
		}
	}
}

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
	run("link", "set", "lo", "up")
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
