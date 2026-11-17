package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Пересылка портов (relay): порт этого VPS → другой сервер, через iptables DNAT + MASQUERADE.
// Формат и цепочки совместимы со скриптом vps-relay/relay-forward.sh: тот же /etc/relay-forward.conf,
// цепочки RELAY-PRE / RELAY-POST (nat) и RELAY-FWD (filter). Входящие правила VPSWall не затрагиваются.

type portForward struct {
	Protocol   string `json:"protocol"`
	ListenPort string `json:"listen_port"`
	Target     string `json:"target"`
	TargetPort string `json:"target_port"`
}

func (f portForward) validate() error {
	if f.Protocol != "tcp" && f.Protocol != "udp" {
		return errors.New("протокол: tcp или udp")
	}
	for _, p := range []string{f.ListenPort, f.TargetPort} {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return errors.New("порт: число от 1 до 65535")
		}
	}
	ip := net.ParseIP(f.Target)
	if ip == nil || ip.To4() == nil || strings.Contains(f.Target, ":") {
		return errors.New("цель: IPv4-адрес")
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("цель: внешний IPv4-адрес")
	}
	return nil
}

func (f portForward) String() string {
	return fmt.Sprintf("%s :%s → %s:%s", f.Protocol, f.ListenPort, f.Target, f.TargetPort)
}

func (m *manager) forwardConf() string { return filepath.Join(m.system, "relay-forward.conf") }

func parseForwards(text string) ([]portForward, error) {
	var out []portForward
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Fields(line)
		if len(p) < 4 {
			return nil, fmt.Errorf("relay-forward.conf, строка %d: нужно «proto порт ip порт»", i+1)
		}
		f := portForward{p[0], p[1], p[2], p[3]}
		if e := f.validate(); e != nil {
			return nil, fmt.Errorf("relay-forward.conf, строка %d: %w", i+1, e)
		}
		out = append(out, f)
	}
	return out, nil
}

func (m *manager) forwards() ([]portForward, error) {
	b, e := os.ReadFile(m.forwardConf())
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	return parseForwards(string(b))
}

func (m *manager) writeForwards(list []portForward) error {
	var b strings.Builder
	b.WriteString("# proto порт_relay ip_цели порт_цели — управляется VPSWall и relay-forward.sh\n")
	for _, f := range list {
		fmt.Fprintf(&b, "%s %s %s %s\n", f.Protocol, f.ListenPort, f.Target, f.TargetPort)
	}
	if e := os.MkdirAll(m.system, 0o755); e != nil {
		return e
	}
	tmp := m.forwardConf() + ".tmp"
	if e := os.WriteFile(tmp, []byte(b.String()), 0o644); e != nil {
		return e
	}
	return os.Rename(tmp, m.forwardConf())
}

func (m *manager) ipt(args ...string) error {
	_, e := m.run("iptables", append([]string{"-w", "5"}, args...)...)
	return e
}

// ensureJump добавляет переход в цепочку, если его ещё нет.
func (m *manager) ensureJump(table, from, to string) error {
	if m.ipt("-t", table, "-C", from, "-j", to) == nil {
		return nil
	}
	return m.ipt("-t", table, "-I", from, "1", "-j", to)
}

// applyForwards пересобирает цепочки RELAY-* из конфига. Идемпотентна.
func (m *manager) applyForwards() error {
	list, e := m.forwards()
	if e != nil {
		return e
	}
	if len(list) == 0 && m.ipt("-t", "nat", "-L", "RELAY-PRE", "-n") != nil {
		return nil // пересылок нет и не было — ничего не создаём
	}
	if _, e = m.run("sysctl", "-qw", "net.ipv4.ip_forward=1"); e != nil {
		return e
	}
	m.ipt("-t", "nat", "-N", "RELAY-PRE")
	m.ipt("-t", "nat", "-N", "RELAY-POST")
	m.ipt("-t", "filter", "-N", "RELAY-FWD")
	if e = m.ensureJump("nat", "PREROUTING", "RELAY-PRE"); e != nil {
		return e
	}
	if e = m.ensureJump("nat", "POSTROUTING", "RELAY-POST"); e != nil {
		return e
	}
	// При Docker цепочка DOCKER-USER проверяется раньше остальных правил FORWARD.
	fwd := "FORWARD"
	if m.ipt("-t", "filter", "-L", "DOCKER-USER", "-n") == nil {
		fwd = "DOCKER-USER"
	}
	if e = m.ensureJump("filter", fwd, "RELAY-FWD"); e != nil {
		return e
	}
	for _, c := range [][]string{{"nat", "RELAY-PRE"}, {"nat", "RELAY-POST"}, {"filter", "RELAY-FWD"}} {
		if e = m.ipt("-t", c[0], "-F", c[1]); e != nil {
			return e
		}
	}
	for _, f := range list {
		rules := [][]string{
			{"-t", "nat", "-A", "RELAY-PRE", "-p", f.Protocol, "--dport", f.ListenPort, "-j", "DNAT", "--to-destination", f.Target + ":" + f.TargetPort, "-m", "comment", "--comment", "relay-forward"},
			{"-t", "nat", "-A", "RELAY-POST", "-p", f.Protocol, "-d", f.Target, "--dport", f.TargetPort, "-j", "MASQUERADE", "-m", "comment", "--comment", "relay-forward"},
			{"-t", "filter", "-A", "RELAY-FWD", "-p", f.Protocol, "-d", f.Target, "--dport", f.TargetPort, "-j", "ACCEPT"},
			{"-t", "filter", "-A", "RELAY-FWD", "-p", f.Protocol, "-s", f.Target, "--sport", f.TargetPort, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		}
		for _, r := range rules {
			if e = m.ipt(r...); e != nil {
				return e
			}
		}
	}
	return nil
}

func (m *manager) portBusy(proto, port string) bool {
	if m.demo {
		return false
	}
	out, _ := m.run("ss", "-H", "-ln"+proto[:1], "sport = :"+port)
	return strings.TrimSpace(out) != ""
}

func (m *manager) addForward(f portForward) error {
	if f.TargetPort == "" {
		f.TargetPort = f.ListenPort
	}
	if e := f.validate(); e != nil {
		return e
	}
	return m.withLock(func() error {
		list, e := m.forwards()
		if e != nil {
			return e
		}
		for _, v := range list {
			if v.Protocol == f.Protocol && v.ListenPort == f.ListenPort {
				return fmt.Errorf("пересылка %s %s уже есть; сначала удалите её", f.Protocol, f.ListenPort)
			}
		}
		if ssh, e := sshRule(m.ssh); e == nil && f.Protocol == "tcp" && ssh.Port == f.ListenPort {
			return errors.New("это текущий SSH-порт; пересылка отрезала бы доступ")
		}
		if m.portBusy(f.Protocol, f.ListenPort) {
			return fmt.Errorf("порт %s/%s уже занят службой на этом сервере", f.ListenPort, f.Protocol)
		}
		if e = m.writeForwards(append(list, f)); e != nil {
			return e
		}
		m.log("FORWARD ADD " + f.String())
		return m.applyForwards()
	})
}

func (m *manager) removeForward(proto, port string) error {
	return m.withLock(func() error {
		list, e := m.forwards()
		if e != nil {
			return e
		}
		var kept []portForward
		var removed *portForward
		for i, v := range list {
			if v.Protocol == proto && v.ListenPort == port {
				removed = &list[i]
			} else {
				kept = append(kept, v)
			}
		}
		if removed == nil {
			return errors.New("пересылка не найдена")
		}
		if e = m.writeForwards(kept); e != nil {
			return e
		}
		m.log("FORWARD DELETE " + removed.String())
		return m.applyForwards()
	})
}

// forwardCounters — вывод счётчиков DNAT (сколько пакетов ушло по каждой пересылке).
func (m *manager) forwardCounters() (string, error) {
	out, e := m.run("iptables", "-w", "5", "-t", "nat", "-L", "RELAY-PRE", "-n", "-v", "-x")
	if e != nil {
		return "", errors.New("цепочка RELAY-PRE не создана: пересылок ещё не было")
	}
	return out, nil
}

func (m *manager) forwardSummary() (string, error) {
	list, e := m.forwards()
	if e != nil {
		return "", e
	}
	if len(list) == 0 {
		return "Пересылок нет.", nil
	}
	var b strings.Builder
	for _, f := range list {
		b.WriteString(f.String() + "\n")
	}
	if out, e := m.forwardCounters(); e == nil {
		b.WriteString("\n" + out)
	}
	return b.String(), nil
}
