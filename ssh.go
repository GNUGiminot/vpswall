package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const sshMarker = "# Managed by VPSWall SSH listener\n"

func validateSSHPort(port string) error {
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return errors.New("SSH-порт: число 1–65535")
	}
	return nil
}
func sshUnit(port string) string { return "vpswall-ssh-" + port + ".service" }
func (m *manager) sshUnitPath(port string) string {
	return filepath.Join(m.system, "systemd", "system", sshUnit(port))
}

// A separate OpenSSH listener preserves the native ssh/sshd service and socket.
// The current config supplies authentication; -p only selects the new listener port.
func (m *manager) prepareSSH(port string) error {
	if e := validateSSHPort(port); e != nil {
		return e
	}
	old, e := sshRule(m.ssh)
	if e != nil {
		return e
	}
	if port == old.Port {
		return errors.New("новый порт совпадает с текущим; выберите «Оставить открытым»")
	}
	if _, e = os.Lstat(m.sshUnitPath(port)); !os.IsNotExist(e) {
		return errors.New("unit нового SSH-порта уже существует; изменения не выполнены")
	}
	if m.demo {
		return nil
	}
	out, e := m.run("ss", "-H", "-ltn", "sport", "=", ":"+port)
	if e != nil {
		return e
	}
	if strings.TrimSpace(out) != "" {
		return errors.New("новый порт уже занят слушающим процессом")
	}
	config := filepath.Join(m.system, "ssh", "sshd_config")
	args := []string{"-f", config, "-p", port}
	if _, e = m.run("sshd", append([]string{"-t"}, args...)...); e != nil {
		return e
	}
	out, e = m.run("sshd", append([]string{"-T"}, args...)...)
	if e != nil {
		return e
	}
	found := false
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "listenaddress" {
			if !strings.HasSuffix(f[1], ":"+port) {
				return errors.New("ListenAddress закрепляет другой порт; настройте SSH вручную")
			}
			found = true
		}
	}
	if !found {
		return errors.New("не удалось проверить адреса нового SSH listener")
	}
	return nil
}
func (m *manager) startSSH(port string) error {
	if e := validateSSHPort(port); e != nil {
		return e
	}
	path := m.sshUnitPath(port)
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return errors.New("SSH unit уже существует")
	}
	body := sshMarker + fmt.Sprintf(`[Unit]
Description=VPSWall additional OpenSSH listener on port %s
After=network.target vpswall-recover.service
[Service]
Type=simple
ExecStart=/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config -p %s -o PidFile=/run/vpswall-ssh-%s/sshd.pid
RuntimeDirectory=vpswall-ssh-%s
KillMode=process
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
`, port, port, port, port)
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	// O_EXCL refuses collisions even when a file appears after preflight.
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if e != nil {
		return e
	}
	_, e = f.WriteString(body)
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", sshUnit(port)}} {
		if _, e = m.run("systemctl", args...); e != nil {
			return e
		}
	}
	if !m.demo {
		if _, e = m.run("systemctl", "is-active", "--quiet", sshUnit(port)); e != nil {
			return e
		}
		// Confirm an actual listener exists; starting a simple service is asynchronous.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			out, err := m.run("ss", "-H", "-ltn", "sport", "=", ":"+port)
			if err != nil {
				return err
			}
			if strings.TrimSpace(out) != "" {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
		return errors.New("SSH не начал слушать новый порт")
	}
	return nil
}
func (m *manager) removeSSH(port string) error {
	if e := validateSSHPort(port); e != nil {
		return e
	}
	path := m.sshUnitPath(port)
	data, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !strings.HasPrefix(string(data), sshMarker) {
		return errors.New("отказ удаления чужого SSH unit")
	}
	if _, e = m.run("systemctl", "disable", "--now", sshUnit(port)); e != nil {
		return e
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	_, e = m.run("systemctl", "daemon-reload")
	return e
}

// SSH source modes: "any" (default — a changed client IP keeps access),
// "subnet" (/24 for IPv4, /64 for IPv6) and "ip" (only the current client).
func sshSource(connection, mode string) (string, error) {
	f := strings.Fields(connection)
	if len(f) != 4 {
		return "", errors.New("SSH_CONNECTION отсутствует: сначала добавьте разрешение на реальный порт SSH")
	}
	addr, e := netip.ParseAddr(f[0])
	if e != nil {
		return "", e
	}
	switch mode {
	case "", "any":
		return "any", nil
	case "ip":
		return addr.String(), nil
	case "subnet":
		bits := 24
		if addr.Is6() && !addr.Is4In6() {
			bits = 64
		}
		prefix, e := addr.Unmap().Prefix(bits)
		if e != nil {
			return "", e
		}
		return prefix.String(), nil
	}
	return "", errors.New("источник SSH: any, subnet или ip")
}
func sshSourceLabel(source string) string {
	if source == "any" {
		return "со всех адресов"
	}
	if strings.Contains(source, "/") {
		return "из подсети " + source
	}
	return "только с IP " + source + " — при смене IP доступ будет потерян"
}
func keepSSH(c managerConfig, connection, mode string) (managerConfig, error) {
	r, e := sshRule(connection)
	if e != nil {
		return c, e
	}
	if r.Source, e = sshSource(connection, mode); e != nil {
		return c, e
	}
	if e = r.validate(); e != nil {
		return c, e
	}
	r.Priority = 0
	c.Rules = append([]managedRule{}, c.Rules...)
	for _, old := range c.Rules {
		if old.Action == r.Action && old.Port == r.Port && old.Protocol == r.Protocol && (old.Source == r.Source || old.Source == "any") {
			return c, nil
		}
	}
	c.Rules = append(c.Rules, r)
	return c, nil
}

// sshLockWarning reports when VPSWall rules let the SSH port in only from fixed
// addresses while other inbound traffic is dropped. Native/foreign rules are not seen.
func sshLockWarning(c managerConfig, port string) string {
	if !c.Enabled || c.Policy == "allow" || port == "" {
		return ""
	}
	var sources []string
	for _, r := range c.Rules {
		if r.Action != "allow" || r.Protocol != "tcp" || !portCovers(r.Port, port) {
			continue
		}
		if r.Source == "any" {
			return ""
		}
		sources = append(sources, r.Source)
	}
	if len(sources) == 0 {
		return "" // allowed by native/foreign rules VPSWall does not inspect
	}
	return "SSH-порт " + port + " разрешён только с " + strings.Join(sources, ", ") + ": при смене IP доступ будет потерян. Добавьте разрешение со всех адресов или из подсети"
}
func portCovers(spec, port string) bool {
	n, e := strconv.Atoi(port)
	if e != nil {
		return false
	}
	lo, hi, found := strings.Cut(spec, ":")
	if !found {
		return spec == port
	}
	a, e1 := strconv.Atoi(lo)
	b, e2 := strconv.Atoi(hi)
	return e1 == nil && e2 == nil && a <= n && n <= b
}

// procSessionStart returns the start time of the nearest sshd ancestor of pid:
// the per-connection sshd/sshd-session process forked when the SSH session began.
// tmux/screen sessions have no such ancestor and are rejected.
func procSessionStart(proc string, pid int) (time.Time, error) {
	statFile, e := os.ReadFile(filepath.Join(proc, "stat"))
	if e != nil {
		return time.Time{}, e
	}
	var boot int64 = -1
	for _, line := range strings.Split(string(statFile), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			boot, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	if boot < 0 {
		return time.Time{}, errors.New("не найден btime в /proc/stat")
	}
	for i := 0; i < 64 && pid > 1; i++ {
		data, e := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "stat"))
		if e != nil {
			return time.Time{}, e
		}
		s := string(data)
		open, end := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || end < open {
			return time.Time{}, errors.New("неверный формат /proc/PID/stat")
		}
		comm := s[open+1 : end]
		fields := strings.Fields(s[end+1:])
		if len(fields) < 20 {
			return time.Time{}, errors.New("неверный формат /proc/PID/stat")
		}
		if comm == "sshd" || comm == "sshd-session" {
			ticks, e := strconv.ParseInt(fields[19], 10, 64)
			if e != nil {
				return time.Time{}, e
			}
			// USER_HZ is 100 on all supported Linux architectures.
			return time.Unix(boot, 0).Add(time.Duration(ticks) * 10 * time.Millisecond), nil
		}
		if pid, e = strconv.Atoi(fields[1]); e != nil {
			return time.Time{}, e
		}
	}
	return time.Time{}, errors.New("команда запущена не из SSH-сеанса (tmux/screen?)")
}
