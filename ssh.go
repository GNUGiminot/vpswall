package main

import (
	"errors"
	"fmt"
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
func keepSSH(c managerConfig, connection string) (managerConfig, error) {
	r, e := sshRule(connection)
	if e != nil {
		return c, e
	}
	r.Priority = 0
	c.Rules = append([]managedRule{}, c.Rules...)
	for _, old := range c.Rules {
		if old.Action == r.Action && old.Port == r.Port && old.Protocol == r.Protocol && old.Source == r.Source {
			return c, nil
		}
	}
	c.Rules = append(c.Rules, r)
	return c, nil
}
