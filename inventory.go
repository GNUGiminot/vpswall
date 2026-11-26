package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Inventory is observational: reading it never selects, enables or imports a firewall.
// Native output preserves ordering, policies, zones, sets and NAT conditions that
// cannot truthfully be reduced to an unconditional list of "open ports".
type systemInventory struct {
	Collected time.Time          `json:"collected"`
	Listeners []listeningPort    `json:"listeners"`
	Firewalls []firewallSnapshot `json:"firewalls"`
	Errors    []string           `json:"errors"`
}
type listeningPort struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     string `json:"port"`
	Scope    string `json:"scope"`
	Process  string `json:"process"`
}
type observedRule struct {
	Number      string `json:"number"`
	Destination string `json:"destination"`
	Action      string `json:"action"`
	Direction   string `json:"direction"`
	Source      string `json:"source"`
	Comment     string `json:"comment"`
}

var ufwNumberedLine = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+)$`)

// Keep service names, interface constraints, IPv6 and direction intact instead
// of interpreting every native rule as an unconditional incoming TCP permission.
func parseUFWNumbered(output string) []observedRule {
	rules := []observedRule{}
	for _, line := range strings.Split(output, "\n") {
		parts := ufwNumberedLine.FindStringSubmatch(strings.TrimSpace(line))
		if parts == nil {
			continue
		}
		source, comment, _ := strings.Cut(parts[5], " # ")
		rules = append(rules, observedRule{parts[1], parts[2], strings.ToLower(parts[3]), parts[4], strings.TrimSpace(source), strings.TrimSpace(comment)})
	}
	return rules
}

type firewallSnapshot struct {
	Backend   string         `json:"backend"`
	Title     string         `json:"title"`
	Output    string         `json:"output"`
	Error     string         `json:"error,omitempty"`
	Truncated bool           `json:"truncated,omitempty"`
	Rules     []observedRule `json:"rules,omitempty"`
}

func parseListeners(output string) ([]listeningPort, error) {
	ports := []listeningPort{}
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 6 || (f[0] != "tcp" && f[0] != "udp") {
			return ports, fmt.Errorf("не удалось разобрать строку ss: %s", line)
		}
		endpoint := f[4]
		i := strings.LastIndexByte(endpoint, ':')
		if i < 0 {
			return ports, fmt.Errorf("неверный адрес ss: %s", endpoint)
		}
		address, port := strings.Trim(endpoint[:i], "[]"), endpoint[i+1:]
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ports, fmt.Errorf("неверный порт ss: %s", endpoint)
		}
		scope := "address"
		if address == "*" || address == "0.0.0.0" || address == "::" {
			scope = "all"
		}
		if addr, err := netip.ParseAddr(address); err == nil && addr.Unmap().IsLoopback() {
			scope = "loopback"
		}
		ports = append(ports, listeningPort{f[0], address, port, scope, strings.Join(f[6:], " ")})
	}
	return ports, nil
}

func (m *manager) inventory() systemInventory {
	inv := systemInventory{Collected: m.now(), Listeners: []listeningPort{}, Firewalls: []firewallSnapshot{}, Errors: []string{}}
	type query struct {
		backend, title, name string
		args                 []string
	}
	queries := []query{}
	installed := func(name string) bool {
		if m.demo {
			return name == "ufw"
		}
		_, err := m.resolve(name)
		return err == nil
	}
	if installed("ufw") {
		queries = append(queries, query{"ufw", "UFW · действующие правила", "ufw", []string{"status", "numbered"}}, query{"ufw", "UFW · сохранённые правила (в том числе при выключенном UFW)", "ufw", []string{"show", "added"}}, query{"ufw", "UFW · состояние и политики", "ufw", []string{"status", "verbose"}})
	}
	if installed("firewall-cmd") {
		queries = append(queries, query{"firewalld", "firewalld · все зоны runtime", "firewall-cmd", []string{"--list-all-zones"}}, query{"firewalld", "firewalld · постоянные зоны", "firewall-cmd", []string{"--permanent", "--list-all-zones"}}, query{"firewalld", "firewalld · direct runtime", "firewall-cmd", []string{"--direct", "--get-all-rules"}})
	}
	if installed("firewall-offline-cmd") {
		queries = append(queries, query{"firewalld", "firewalld · конфигурация на диске", "firewall-offline-cmd", []string{"--list-all-zones"}})
	}
	if installed("nft") {
		queries = append(queries, query{"nftables", "nftables · весь ruleset, включая NAT и сторонние таблицы", "nft", []string{"-a", "list", "ruleset"}})
	}
	for _, name := range []string{"iptables-save", "ip6tables-save"} {
		if installed(name) {
			queries = append(queries, query{"iptables", name + " · все таблицы", name, nil})
		}
	}
	// Bounded parallelism: one read per installed tool, no shell and no mutations.
	results := make([]firewallSnapshot, len(queries))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 10)
	for i, q := range queries {
		wg.Add(1)
		go func(i int, q query) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			output, err := m.run(q.name, q.args...)
			snapshot := firewallSnapshot{Backend: q.backend, Title: q.title, Output: output}
			if len(snapshot.Output) > 262144 {
				snapshot.Output = strings.ToValidUTF8(snapshot.Output[:262144], "")
				snapshot.Truncated = true
			}
			if err != nil {
				snapshot.Error = err.Error()
				if len(snapshot.Error) > 16384 {
					snapshot.Error = strings.ToValidUTF8(snapshot.Error[:16384], "") + "…"
				}
			}
			if q.name == "ufw" && len(q.args) > 1 && q.args[0] == "status" && q.args[1] == "numbered" && err == nil {
				snapshot.Rules = parseUFWNumbered(snapshot.Output)
			}
			results[i] = snapshot
		}(i, q)
	}
	out, err := m.run("ss", "-H", "-lntup")
	if err != nil {
		inv.Errors = append(inv.Errors, "Слушающие порты: "+err.Error())
	} else {
		inv.Listeners, err = parseListeners(out)
		if err != nil {
			inv.Errors = append(inv.Errors, err.Error())
		}
	}
	wg.Wait()
	inv.Firewalls = results
	return inv
}

func (inv systemInventory) text() string {
	var b strings.Builder
	b.WriteString("СЛУШАЮЩИЕ ПОРТЫ (это не проверка доступности извне)\n")
	for _, p := range inv.Listeners {
		fmt.Fprintf(&b, "%s %s:%s [%s] %s\n", p.Protocol, p.Address, p.Port, p.Scope, p.Process)
	}
	if len(inv.Listeners) == 0 {
		b.WriteString("Слушающих TCP/UDP-портов не обнаружено.\n")
	}
	for _, e := range inv.Errors {
		fmt.Fprintf(&b, "Ошибка: %s\n", e)
	}
	for _, s := range inv.Firewalls {
		fmt.Fprintf(&b, "\n%s\n%s\n", s.Title, s.Output)
		if s.Error != "" {
			fmt.Fprintf(&b, "Ошибка чтения: %s\n", s.Error)
		}
		if s.Truncated {
			b.WriteString("Вывод сокращён до 256 КиБ; используйте системную команду для полного списка.\n")
		}
	}
	if len(inv.Firewalls) == 0 {
		b.WriteString("\nИнструменты чтения firewall не установлены.\n")
	}
	return b.String()
}

// Cache native reads separately from the mutation lock. A slow firewall command
// must never prevent rollback or confirmation; observations expire after 10 s.
func (s *webServer) systemInventory() systemInventory {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()
	if s.inventoryCache.Collected.IsZero() || time.Since(s.inventoryCachedAt) >= 10*time.Second {
		s.inventoryCache = s.m.inventory()
		s.inventoryCachedAt = time.Now()
	}
	return s.inventoryCache
}
