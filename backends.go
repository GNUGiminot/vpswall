package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var zonePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)
var binaryPaths = map[string][]string{
	"sshd": {"/usr/sbin/sshd"},
	"ufw":  {"/usr/sbin/ufw"}, "systemctl": {"/usr/bin/systemctl"}, "systemd-run": {"/usr/bin/systemd-run"}, "cp": {"/usr/bin/cp"},
	"ss": {"/usr/bin/ss", "/usr/sbin/ss"}, "journalctl": {"/usr/bin/journalctl"},
	"firewall-cmd": {"/usr/bin/firewall-cmd"}, "firewall-offline-cmd": {"/usr/bin/firewall-offline-cmd"},
	"nft": {"/usr/sbin/nft", "/sbin/nft"}, "iptables": {"/usr/sbin/iptables", "/sbin/iptables"}, "ip6tables": {"/usr/sbin/ip6tables", "/sbin/ip6tables"},
	"iptables-restore": {"/usr/sbin/iptables-restore", "/sbin/iptables-restore"}, "ip6tables-restore": {"/usr/sbin/ip6tables-restore", "/sbin/ip6tables-restore"},
	"iptables-save": {"/usr/sbin/iptables-save", "/sbin/iptables-save"}, "ip6tables-save": {"/usr/sbin/ip6tables-save", "/sbin/ip6tables-save"},
	"apt-get": {"/usr/bin/apt-get"}, "dnf": {"/usr/bin/dnf"}, "certbot": {"/usr/bin/certbot", "/snap/bin/certbot"},
}

func binary(name string) (string, error) {
	for _, p := range binaryPaths[name] {
		if st, e := os.Stat(p); e == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("не установлен инструмент %s", name)
}
func managerCommand(name string, args ...string) (string, error) {
	var stdin *os.File
	if strings.HasSuffix(name, "-file") {
		name = strings.TrimSuffix(name, "-file")
		if len(args) == 0 {
			return "", errors.New("не задан входной файл")
		}
		var e error
		stdin, e = os.Open(args[0])
		if e != nil {
			return "", e
		}
		defer stdin.Close()
		args = args[1:]
	}
	p, e := binary(name)
	if e != nil {
		return "", e
	}
	timeout := 25 * time.Second
	if name == "apt-get" || name == "dnf" || name == "certbot" {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Stdin = stdin
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin", "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive"}
	out, e := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s: время выполнения истекло", name)
	}
	if e != nil {
		return string(out), fmt.Errorf("%s: %w\n%s", name, e, out)
	}
	return string(out), nil
}
func backendBinary(b string) string {
	switch b {
	case "firewalld":
		return "firewall-cmd"
	case "nftables":
		return "nft"
	default:
		return b
	}
}
func (m *manager) nativeActive(b string) (bool, error) {
	switch b {
	case "ufw":
		out, e := m.run("ufw", "status")
		return strings.HasPrefix(strings.TrimSpace(out), "Status: active"), e
	case "firewalld":
		out, e := m.run("firewall-cmd", "--state")
		return strings.TrimSpace(out) == "running", e
	default:
		return false, nil
	}
}
func (m *manager) conflicts(b string) error {
	if m.demo {
		return nil
	}
	if b != "ufw" {
		if active, _ := m.nativeActive("ufw"); active {
			return errors.New("UFW уже активен. Сначала отключите его самостоятельно; автоматическая миграция чужих правил не выполняется")
		}
	}
	if b != "firewalld" {
		if active, _ := m.nativeActive("firewalld"); active {
			return errors.New("firewalld уже активен. Сначала отключите его; выбранный backend не будет запущен параллельно")
		}
	}
	if b == "nftables" {
		if _, e := binary("nft"); e == nil {
			out, e := m.run("nft", "-j", "list", "ruleset")
			if e != nil {
				return e
			}
			if foreignNFTInput(out) {
				return errors.New("есть чужие входящие base chains nftables. Они могут отменить разрешения VPSWall; требуется ручная миграция")
			}
		}
	}
	return nil
}
func foreignNFTInput(out string) bool {
	var doc struct {
		NFT []struct {
			Chain *struct {
				Table string `json:"table"`
				Hook  string `json:"hook"`
			} `json:"chain"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return true
	}
	for _, obj := range doc.NFT {
		if obj.Chain != nil && obj.Chain.Hook == "input" && obj.Chain.Table != "vpswall" {
			return true
		}
	}
	return false
}
func (m *manager) installBackend(b string) error {
	if m.demo {
		return nil
	}
	if _, e := m.resolve(backendBinary(b)); e == nil {
		return nil
	}
	pkg := b
	if b == "firewalld" {
		pkg = "firewalld"
	}
	installer := ""
	if _, e := m.resolve("apt-get"); e == nil {
		installer = "apt-get"
	} else if _, e := m.resolve("dnf"); e == nil {
		installer = "dnf"
	} else {
		return fmt.Errorf("установите %s вручную: поддержаны apt-get и dnf", pkg)
	}
	// Prevent package scripts from starting a firewall before SSH rules are staged.
	service := ""
	switch b {
	case "ufw":
		service = "ufw.service"
	case "firewalld":
		service = "firewalld.service"
	case "nftables":
		service = "nftables.service"
	}
	if service != "" {
		out, _ := m.run("systemctl", "is-enabled", service)
		if strings.Contains(out, "masked") {
			return errors.New("служба уже замаскирована администратором; снимите маску вручную")
		}
		if _, e := m.run("systemctl", "mask", "--runtime", service); e != nil {
			return e
		}
		defer m.run("systemctl", "unmask", "--runtime", service)
	}
	if installer == "apt-get" {
		if _, e := m.run(installer, "update"); e != nil {
			return e
		}
	}
	if _, e := m.run(installer, "install", "-y", pkg); e != nil {
		return e
	}
	if service != "" {
		if _, e := m.run("systemctl", "disable", service); e != nil {
			return e
		}
	}
	_, e := m.resolve(backendBinary(b))
	return e
}
func (m *manager) rawStatus(c managerConfig) (string, error) {
	switch c.Backend {
	case "ufw":
		a, e := m.run("ufw", "status", "verbose")
		if e != nil {
			return a, e
		}
		b, e := m.run("ufw", "status", "numbered")
		return a + "\n" + b, e
	case "firewalld":
		a, e := m.run("firewall-cmd", "--get-active-zones")
		if e != nil {
			return a, e
		}
		b, e := m.run("firewall-cmd", "--zone="+c.Zone, "--list-all")
		return a + "\n" + b, e
	case "nftables":
		return m.run("nft", "-a", "list", "ruleset")
	case "iptables":
		a, e := m.run("iptables", "-S")
		if e != nil {
			return a, e
		}
		b, e := m.run("ip6tables", "-S")
		return "IPv4\n" + a + "\nIPv6\n" + b, e
	}
	return "Сначала выберите сетевой экран", nil
}
func (m *manager) applyBackend(c managerConfig, wanted []managedRule, old ownedBook) error {
	if m.demo {
		return nil
	}
	if c.Enabled {
		if e := m.conflicts(c.Backend); e != nil {
			return e
		}
	}
	switch c.Backend {
	case "ufw":
		return m.applyUFW(c, wanted, old.Rules)
	case "firewalld":
		return m.applyFirewalld(c, wanted, old)
	case "nftables":
		return m.applyNFT(c, wanted)
	case "iptables":
		return m.applyIPTables(c, wanted)
	}
	return errors.New("неверный backend")
}
func (m *manager) preflightBackend(c managerConfig, wanted []managedRule, old ownedBook) error {
	if m.demo {
		return nil
	}
	if c.Enabled {
		if e := m.conflicts(c.Backend); e != nil {
			return e
		}
	}
	if c.Backend != "firewalld" {
		return nil
	}
	active, _ := m.nativeActive("firewalld")
	owned := map[string]bool{}
	for i, r := range old.Rules {
		owned[richRule(r, i)] = true
	}
	if old.Policy == "deny" {
		owned[firePolicy("ipv4")] = true
		owned[firePolicy("ipv6")] = true
	}
	var expressions []string
	for i, r := range wanted {
		expressions = append(expressions, richRule(r, i))
	}
	if c.Enabled && c.Policy == "deny" {
		expressions = append(expressions, firePolicy("ipv4"), firePolicy("ipv6"))
	}
	for _, expr := range expressions {
		if owned[expr] {
			continue
		}
		for _, permanent := range []bool{true, false} {
			if !active && !permanent {
				continue
			}
			name := "firewall-cmd"
			args := []string{"--zone=" + c.Zone}
			if !active {
				name = "firewall-offline-cmd"
			} else if permanent {
				args = append(args, "--permanent")
			}
			args = append(args, "--query-rich-rule="+expr)
			out, e := m.run(name, args...)
			if e == nil && strings.TrimSpace(out) == "yes" {
				return errors.New("правило совпадает с существующим чужим rich rule; оно не будет присвоено VPSWall")
			}
		}
	}
	return nil
}
func (m *manager) applyUFW(c managerConfig, wanted, known []managedRule) error {
	out, e := m.run("ufw", "show", "added")
	if e != nil {
		return e
	}
	for _, r := range known {
		if strings.Contains(out, "VPSWall:"+r.ID) {
			args := append([]string{"--force", "delete"}, r.ufwArgs()...)
			if _, e = m.run("ufw", args...); e != nil {
				return e
			}
		}
	}
	desired := sortedRules(wanted)
	// prepend does not update comments on existing duplicate rules. Detect collisions.
	for i := len(desired) - 1; i >= 0; i-- {
		r := desired[i]
		args := append([]string{"prepend"}, r.ufwArgs()...)
		if _, e = m.run("ufw", args...); e != nil {
			return e
		}
		actual, e := m.run("ufw", "show", "added")
		if e != nil {
			return e
		}
		if !strings.Contains(actual, "VPSWall:"+r.ID) {
			if r.AutoSSH {
				continue
			}
			return fmt.Errorf("правило %s совпадает с существующим чужим правилом; оно не присвоено VPSWall", r.Port)
		}
	}
	status, e := m.run("ufw", "status", "verbose")
	if e != nil {
		return e
	}
	active := strings.HasPrefix(strings.TrimSpace(status), "Status: active")
	// Only change a native policy when it differs; imported UFW policy is captured at selection.
	if !strings.Contains(status, "Default: "+c.Policy+" (incoming)") {
		if _, e = m.run("ufw", "default", c.Policy, "incoming"); e != nil {
			return e
		}
	}
	if c.Enabled && !active {
		_, e = m.run("ufw", "--force", "enable")
	} else if !c.Enabled && active {
		_, e = m.run("ufw", "--force", "disable")
	}
	return e
}
func richRule(r managedRule, index int) string {
	family := ""
	source := ""
	if r.Source != "" && r.Source != "any" {
		ip := strings.Split(r.Source, "/")[0]
		addr, _ := netip.ParseAddr(ip)
		family = " family=\"ipv4\""
		if addr.Is6() {
			family = " family=\"ipv6\""
		}
		source = " source address=\"" + r.Source + "\""
	}
	// Earlier array elements get a lower priority. Temporary openings precede permanent denies.
	priority := -20000 + r.Priority
	if r.Temporary {
		priority = -32000 + r.Priority
	}
	action := map[string]string{"allow": "accept", "deny": "drop", "reject": "reject"}[r.Action]
	return fmt.Sprintf("rule priority=\"%d\"%s%s port port=\"%s\" protocol=\"%s\" %s", priority, family, source, strings.ReplaceAll(r.Port, ":", "-"), r.Protocol, action)
}
func firePolicy(family string) string {
	return "rule priority=\"32765\" family=\"" + family + "\" drop"
}
func (m *manager) fireCommand(active, permanent bool, zone, operation, expr string) error {
	name := "firewall-cmd"
	args := []string{"--zone=" + zone}
	if !active {
		name = "firewall-offline-cmd"
	} else if permanent {
		args = append(args, "--permanent")
	}
	args = append(args, "--"+operation+"-rich-rule="+expr)
	query := append([]string{}, args...)
	query[len(query)-1] = "--query-rich-rule=" + expr
	out, e := m.run(name, query...)
	present := e == nil && strings.TrimSpace(out) == "yes"
	if operation == "remove" && !present {
		return nil
	}
	if operation == "add" && present {
		return nil
	}
	_, e = m.run(name, args...)
	return e
}
func (m *manager) applyFirewalld(c managerConfig, wanted []managedRule, old ownedBook) error {
	active, _ := m.nativeActive("firewalld")
	known := old.Rules
	// An identical foreign rich rule must never become a rule that VPSWall later removes.
	previous := map[string]bool{}
	for i, r := range known {
		previous[richRule(r, i)] = true
	}
	for i, r := range wanted {
		expr := richRule(r, i)
		if previous[expr] {
			continue
		}
		name := "firewall-cmd"
		args := []string{"--zone=" + c.Zone, "--permanent", "--query-rich-rule=" + expr}
		if !active {
			name = "firewall-offline-cmd"
			args = []string{"--zone=" + c.Zone, "--query-rich-rule=" + expr}
		}
		if out, e := m.run(name, args...); e == nil && strings.TrimSpace(out) == "yes" {
			return errors.New("такое rich rule уже существует вне VPSWall")
		}
		if active {
			if out, e := m.run("firewall-cmd", "--zone="+c.Zone, "--query-rich-rule="+expr); e == nil && strings.TrimSpace(out) == "yes" {
				return errors.New("такое временное rich rule уже существует вне VPSWall")
			}
		}
	}
	// Stage permanent owned rules offline before first service start.
	if c.Enabled && !active {
		for i, r := range sortedRules(wanted) {
			if !r.Temporary {
				if e := m.fireCommand(false, true, c.Zone, "add", richRule(r, i)); e != nil {
					return e
				}
			}
		}
		if _, e := m.run("systemctl", "start", "firewalld.service"); e != nil {
			return e
		}
		active = true
	}
	// Remove only expressions in the ownership journal, never a zone or all rich rules.
	for i, r := range sortedRules(known) {
		expr := richRule(r, i)
		if active {
			if e := m.fireCommand(true, false, c.Zone, "remove", expr); e != nil {
				return e
			}
		}
		if !r.Temporary {
			if e := m.fireCommand(active, true, c.Zone, "remove", expr); e != nil {
				return e
			}
		}
	}
	for i, r := range sortedRules(wanted) {
		expr := richRule(r, i)
		if !r.Temporary {
			if e := m.fireCommand(active, true, c.Zone, "add", expr); e != nil {
				return e
			}
		}
		if active {
			args := []string{"--zone=" + c.Zone, "--add-rich-rule=" + expr}
			if r.Temporary {
				remaining := int(r.Until.Sub(m.now()).Seconds())
				if remaining < 1 {
					continue
				}
				args = append(args, "--timeout="+strconv.Itoa(remaining))
			}
			if _, e := m.run("firewall-cmd", args...); e != nil {
				return e
			}
		}
	}
	// Policy rules are confined to this zone and run after native service/port accepts.
	for _, family := range []string{"ipv4", "ipv6"} {
		operation := "remove"
		if c.Enabled && c.Policy == "deny" {
			operation = "add"
		}
		if operation == "remove" && old.Policy != "deny" {
			continue
		}
		expr := firePolicy(family)
		if operation == "add" && old.Policy != "deny" {
			name := "firewall-cmd"
			args := []string{"--zone=" + c.Zone, "--permanent", "--query-rich-rule=" + expr}
			if !active {
				name = "firewall-offline-cmd"
				args = []string{"--zone=" + c.Zone, "--query-rich-rule=" + expr}
			}
			if out, e := m.run(name, args...); e == nil && strings.TrimSpace(out) == "yes" {
				return errors.New("политика VPSWall совпала с чужим rich rule")
			}
		}
		if e := m.fireCommand(active, true, c.Zone, operation, expr); e != nil {
			return e
		}
		if active {
			if e := m.fireCommand(true, false, c.Zone, operation, expr); e != nil {
				return e
			}
		}
	}
	if !c.Enabled && active {
		_, e := m.run("systemctl", "stop", "firewalld.service")
		return e
	}
	return nil
}
func nftRule(r managedRule) string {
	parts := []string{}
	if r.Source != "" && r.Source != "any" {
		addr, _ := netip.ParseAddr(strings.Split(r.Source, "/")[0])
		family := "ip"
		if addr.Is6() {
			family = "ip6"
		}
		parts = append(parts, family, "saddr", r.Source)
	}
	parts = append(parts, r.Protocol, "dport", strings.ReplaceAll(r.Port, ":", "-"), "counter", map[string]string{"allow": "accept", "deny": "drop", "reject": "reject"}[r.Action], "comment", strconv.Quote("VPSWall:"+r.ID))
	return strings.Join(parts, " ")
}
func nftScript(c managerConfig, rules []managedRule, exists bool) string {
	var b strings.Builder
	if exists {
		b.WriteString("delete table inet vpswall\n")
	}
	if !c.Enabled {
		return b.String()
	}
	policy := map[string]string{"allow": "accept", "deny": "drop"}[c.Policy]
	b.WriteString("table inet vpswall {\n comment \"VPSWall managed\"\n chain input {\n type filter hook input priority 0; policy " + policy + ";\n ct state established,related accept\n iifname \"lo\" accept\n meta l4proto { icmp, ipv6-icmp } accept\n")
	for _, r := range sortedRules(rules) {
		b.WriteString(" " + nftRule(r) + "\n")
	}
	b.WriteString(" }\n}\n")
	return b.String()
}
func (m *manager) applyNFT(c managerConfig, rules []managedRule) error {
	out, e := m.run("nft", "-j", "list", "table", "inet", "vpswall")
	exists := e == nil
	if e != nil && !strings.Contains(e.Error(), "No such file or directory") {
		return e
	}
	if exists && !nftOwned(out) {
		return errors.New("таблица inet vpswall уже занята чужой конфигурацией")
	}
	script := nftScript(c, rules, exists)
	if script == "" {
		return nil
	}
	path := m.path("nft-batch.rules")
	if e = os.WriteFile(path, []byte(script), 0600); e != nil {
		return e
	}
	if _, e = m.run("nft", "-c", "-f", path); e != nil {
		return e
	}
	_, e = m.run("nft", "-f", path)
	return e
}
func nftOwned(out string) bool {
	var doc struct {
		NFT []struct {
			Table *struct{ Family, Name, Comment string } `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return false
	}
	for _, obj := range doc.NFT {
		if obj.Table != nil && obj.Table.Family == "inet" && obj.Table.Name == "vpswall" && obj.Table.Comment == "VPSWall managed" {
			return true
		}
	}
	return false
}
func iptRule(r managedRule, ipv6 bool) string {
	if r.Source != "" && r.Source != "any" {
		addr, _ := netip.ParseAddr(strings.Split(r.Source, "/")[0])
		if addr.Is6() != ipv6 {
			return ""
		}
	}
	source := ""
	if r.Source != "" && r.Source != "any" {
		source = " -s " + r.Source
	}
	return "-A VPSWALL_IN -p " + r.Protocol + source + " --dport " + r.Port + " -m comment --comment " + strconv.Quote("VPSWall:"+r.ID) + " -j " + map[string]string{"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT"}[r.Action] + "\n"
}
func iptScript(c managerConfig, rules []managedRule, ipv6 bool) string {
	var b strings.Builder
	b.WriteString("*filter\n:VPSWALL_IN - [0:0]\n-F VPSWALL_IN\n-A VPSWALL_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n-A VPSWALL_IN -i lo -j ACCEPT\n")
	proto := "icmp"
	if ipv6 {
		proto = "ipv6-icmp"
	}
	b.WriteString("-A VPSWALL_IN -p " + proto + " -j ACCEPT\n")
	for _, r := range sortedRules(rules) {
		b.WriteString(iptRule(r, ipv6))
	}
	target := "RETURN"
	if c.Policy == "deny" {
		target = "DROP"
	}
	b.WriteString("-A VPSWALL_IN -m comment --comment \"VPSWall:owner\" -j " + target + "\nCOMMIT\n")
	return b.String()
}
func (m *manager) applyIPTables(c managerConfig, rules []managedRule) error {
	for _, name := range []string{"iptables", "ip6tables"} {
		ipv6 := name == "ip6tables"
		out, e := m.run(name, "-w", "5", "-S", "VPSWALL_IN")
		exists := e == nil
		if e != nil && !strings.Contains(e.Error(), "No chain/target/match") && !strings.Contains(e.Error(), "does not exist") {
			return e
		}
		if exists && !strings.Contains(out, "VPSWall:owner") {
			return errors.New("цепочка VPSWALL_IN уже занята чужой конфигурацией")
		}
		hook := []string{"-w", "5", "-C", "INPUT", "-m", "comment", "--comment", "VPSWall:hook", "-j", "VPSWALL_IN"}
		_, hookErr := m.run(name, hook...)
		if !c.Enabled {
			if hookErr == nil {
				args := append([]string{}, hook...)
				args[2] = "-D"
				if _, e = m.run(name, args...); e != nil {
					return e
				}
			}
			if exists {
				if _, e = m.run(name, "-w", "5", "-F", "VPSWALL_IN"); e != nil {
					return e
				}
				if _, e = m.run(name, "-w", "5", "-X", "VPSWALL_IN"); e != nil {
					return e
				}
			}
			continue
		}
		path := m.path(name + "-batch.rules")
		if e = os.WriteFile(path, []byte(iptScript(c, rules, ipv6)), 0600); e != nil {
			return e
		}
		if _, e = m.run(name+"-restore-file", path, "--test", "--noflush", "--wait", "5"); e != nil {
			return e
		}
		if _, e = m.run(name+"-restore-file", path, "--noflush", "--wait", "5"); e != nil {
			return e
		}
		if hookErr != nil {
			if _, e = m.run(name, "-w", "5", "-I", "INPUT", "1", "-m", "comment", "--comment", "VPSWall:hook", "-j", "VPSWALL_IN"); e != nil {
				return e
			}
		}
	}
	return nil
}
