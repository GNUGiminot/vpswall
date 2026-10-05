package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
)

type managedRule struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	Protocol  string    `json:"protocol"`
	Port      string    `json:"port"`
	Source    string    `json:"source"`
	Comment   string    `json:"comment"`
	Priority  int       `json:"priority"`
	AutoSSH   bool      `json:"auto_ssh,omitempty"`
	Temporary bool      `json:"temporary,omitempty"`
	Until     time.Time `json:"until,omitempty"`
}

func (r managedRule) validate() error {
	if !idPattern.MatchString(r.ID) {
		return errors.New("неверный ID правила")
	}
	if r.Priority < 0 || r.Priority > 9999 {
		return errors.New("приоритет: 0–9999, меньше — раньше")
	}
	if r.Action != "allow" && r.Action != "deny" && r.Action != "reject" {
		return errors.New("действие: allow, deny, reject")
	}
	_, e := (rule{Action: mapAction(r.Action), Protocol: r.Protocol, Port: r.Port, Source: r.Source, Comment: r.Comment}).args()
	return e
}
func mapAction(s string) string {
	if s == "reject" {
		return "deny"
	}
	return s
}
func (r managedRule) ufwArgs() []string {
	args, _ := (rule{Action: mapAction(r.Action), Protocol: r.Protocol, Port: r.Port, Source: r.Source, Comment: "VPSWall:" + r.ID}).args()
	args[0] = r.Action
	return args
}
func newManaged(action, proto, port, source, comment string) (managedRule, error) {
	id, e := newID()
	r := managedRule{ID: id, Action: action, Protocol: proto, Port: port, Source: source, Comment: comment, Priority: 5000}
	if r.Source == "" {
		r.Source = "any"
	}
	if addr, err := netip.ParseAddr(r.Source); err == nil {
		r.Source = addr.String()
	} else if prefix, err := netip.ParsePrefix(r.Source); err == nil {
		r.Source = prefix.Masked().String()
	}
	if e == nil {
		e = r.validate()
	}
	return r, e
}

type managerConfig struct {
	Backend string        `json:"backend"`
	Zone    string        `json:"zone"`
	Enabled bool          `json:"enabled"`
	Policy  string        `json:"policy"`
	Rules   []managedRule `json:"rules"`
}
type window struct {
	ID      string      `json:"id"`
	Rule    managedRule `json:"rule"`
	Kind    string      `json:"kind"` // once, daily, lease
	Start   time.Time   `json:"start,omitempty"`
	Clock   string      `json:"clock,omitempty"`
	Zone    string      `json:"zone,omitempty"`
	Seconds int64       `json:"seconds"`
	Paused  bool        `json:"paused,omitempty"`
	Purpose string      `json:"purpose,omitempty"`
}

func clockParts(s string) (int, int, error) {
	p := strings.Split(s, ":")
	if len(p) != 2 || len(p[0]) != 2 || len(p[1]) != 2 {
		return 0, 0, errors.New("время: ЧЧ:ММ, например 03:15")
	}
	h, e := strconv.Atoi(p[0])
	if e != nil || h < 0 || h > 23 {
		return 0, 0, errors.New("неверный час")
	}
	m, e := strconv.Atoi(p[1])
	if e != nil || m < 0 || m > 59 {
		return 0, 0, errors.New("неверная минута")
	}
	return h, m, nil
}
func (w window) validate() error {
	if !idPattern.MatchString(w.ID) || w.Rule.ID != w.ID {
		return errors.New("неверный ID окна")
	}
	if e := w.Rule.validate(); e != nil {
		return e
	}
	if w.Rule.Action != "allow" {
		return errors.New("окно может только разрешать порт")
	}
	if w.Seconds < 60 || w.Seconds > 86400 {
		return errors.New("длительность: от 1 минуты до 24 часов")
	}
	switch w.Kind {
	case "daily":
		if _, _, e := clockParts(w.Clock); e != nil {
			return e
		}
		if _, e := time.LoadLocation(w.Zone); e != nil {
			return e
		}
		if w.Seconds >= 86400 {
			return errors.New("ежедневное окно должно быть короче 24 часов")
		}
	case "once", "lease":
		if w.Start.IsZero() {
			return errors.New("не задано начало окна")
		}
	default:
		return errors.New("тип окна: once, daily, lease")
	}
	return nil
}
func (w window) interval(now time.Time) (time.Time, time.Time, bool) {
	if w.Paused {
		return time.Time{}, time.Time{}, false
	}
	start := w.Start
	if w.Kind == "daily" {
		loc, e := time.LoadLocation(w.Zone)
		if e != nil {
			return time.Time{}, time.Time{}, false
		}
		h, m, e := clockParts(w.Clock)
		if e != nil {
			return time.Time{}, time.Time{}, false
		}
		local := now.In(loc)
		start = time.Date(local.Year(), local.Month(), local.Day(), h, m, 0, 0, loc)
		if now.Before(start) {
			prev := local.AddDate(0, 0, -1)
			start = time.Date(prev.Year(), prev.Month(), prev.Day(), h, m, 0, 0, loc)
		}
	}
	end := start.Add(time.Duration(w.Seconds) * time.Second)
	return start, end, !now.Before(start) && now.Before(end)
}
func (w window) next(now time.Time) time.Time {
	if w.Kind != "daily" {
		return w.Start
	}
	loc, e := time.LoadLocation(w.Zone)
	if e != nil {
		return time.Time{}
	}
	h, m, e := clockParts(w.Clock)
	if e != nil {
		return time.Time{}
	}
	local := now.In(loc)
	n := time.Date(local.Year(), local.Month(), local.Day(), h, m, 0, 0, loc)
	if !now.Before(n) {
		d := local.AddDate(0, 0, 1)
		n = time.Date(d.Year(), d.Month(), d.Day(), h, m, 0, 0, loc)
	}
	return n
}

type ownedBook struct {
	Backend string        `json:"backend"`
	Zone    string        `json:"zone"`
	Rules   []managedRule `json:"rules"`
	Policy  string        `json:"policy"`
}
type managerChange struct {
	Token       string        `json:"token"`
	Before      managerConfig `json:"before"`
	SSH         string        `json:"ssh"`
	Deadline    time.Time     `json:"deadline"`
	Ready       bool          `json:"ready"`
	Description string        `json:"description"`
	SSHPort     string        `json:"ssh_port,omitempty"`
}
type manager struct {
	root, system, runtimeDir string
	run                      func(string, ...string) (string, error)
	now                      func() time.Time
	ssh                      string
	demo                     bool
	lookup                   func(string) (string, error)
}

func (m *manager) resolve(name string) (string, error) {
	if m.lookup != nil {
		return m.lookup(name)
	}
	return binary(name)
}

func (m *manager) path(name string) string { return filepath.Join(m.root, name) }
func (m *manager) config() (managerConfig, error) {
	var c managerConfig
	e := readJSON(m.path("manager.json"), &c)
	if errors.Is(e, os.ErrNotExist) {
		return managerConfig{Zone: "public", Policy: "allow"}, nil
	}
	if e == nil {
		e = validateConfig(c)
	}
	return c, e
}
func validateConfig(c managerConfig) error {
	if !validBackend(c.Backend) {
		return errors.New("неверный backend")
	}
	if c.Policy != "allow" && c.Policy != "deny" && !(c.Backend == "ufw" && c.Policy == "reject") {
		return errors.New("политика: allow или deny")
	}
	if !zonePattern.MatchString(c.Zone) {
		return errors.New("неверная зона")
	}
	seen := map[string]bool{}
	for _, r := range c.Rules {
		if e := r.validate(); e != nil {
			return e
		}
		if seen[r.ID] {
			return errors.New("повторный ID правила")
		}
		seen[r.ID] = true
	}
	return nil
}
func validBackend(b string) bool {
	return b == "ufw" || b == "firewalld" || b == "nftables" || b == "iptables"
}
func (m *manager) windows() ([]window, error) {
	var w []window
	e := readJSON(m.path("windows.json"), &w)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	for _, v := range w {
		if e = v.validate(); e != nil {
			return nil, e
		}
	}
	return w, nil
}
func (m *manager) pending() (*managerChange, error) {
	var p managerChange
	e := readJSON(m.path("change.json"), &p)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if !idPattern.MatchString(p.Token) || p.Deadline.IsZero() {
		return nil, errors.New("повреждено состояние транзакции")
	}
	if e = validateConfig(p.Before); e != nil {
		return nil, e
	}
	if p.SSHPort != "" {
		if e = validateSSHPort(p.SSHPort); e != nil {
			return nil, e
		}
	}
	return &p, nil
}
func (m *manager) withLock(fn func() error) error {
	unlock, e := lockState(m.path("manager.lock"))
	if e != nil {
		return e
	}
	defer unlock()
	return fn()
}
func (m *manager) log(message string) { a := &app{state: m.root, now: m.now}; a.audit(message) }
func (m *manager) desired(c managerConfig) ([]managedRule, error) {
	desired := append([]managedRule{}, c.Rules...)
	windows, e := m.windows()
	if e != nil {
		return nil, e
	}
	for _, w := range windows {
		if _, end, active := w.interval(m.now()); active {
			r := w.Rule
			r.Temporary = true
			r.Until = end
			desired = append(desired, r)
		}
	}
	if !c.Enabled {
		return nil, nil
	}
	// Overlapping windows share one permission; a pre-existing permanent allow survives closure.
	seen := map[string]int{}
	var unique []managedRule
	for _, r := range desired {
		key := r.Action + "|" + r.Protocol + "|" + r.Port + "|" + r.Source
		if i, ok := seen[key]; ok {
			if unique[i].Temporary && r.Until.After(unique[i].Until) {
				unique[i].Until = r.Until
			}
			continue
		}
		seen[key] = len(unique)
		unique = append(unique, r)
	}
	return unique, nil
}
func (m *manager) synchronize(c managerConfig, force bool) error {
	if c.Backend == "" {
		return nil
	}
	if e := validateConfig(c); e != nil {
		return e
	}
	desired, e := m.desired(c)
	if e != nil {
		return e
	}
	var old ownedBook
	e = readJSON(m.path("owned.json"), &old)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if old.Backend != "" && old.Backend != c.Backend && len(old.Rules) > 0 {
		return errors.New("другой backend ещё содержит правила VPSWall")
	}
	if old.Zone != "" && old.Zone != c.Zone && len(old.Rules) > 0 {
		return errors.New("сначала удалите правила старой зоны")
	}
	for _, r := range old.Rules {
		if e = r.validate(); e != nil {
			return e
		}
	}
	// Journal intent before any kernel mutation, so interrupted operations can be cleaned up.
	union := append([]managedRule{}, old.Rules...)
	seen := map[string]bool{}
	for _, r := range union {
		seen[r.ID] = true
	}
	for _, r := range desired {
		if !seen[r.ID] {
			union = append(union, r)
			seen[r.ID] = true
		}
	}
	journal := ownedBook{Backend: c.Backend, Zone: c.Zone, Rules: union, Policy: "allow"}
	if old.Policy == "deny" || c.Policy == "deny" {
		journal.Policy = "deny"
	}
	b, _ := json.Marshal(struct {
		Config managerConfig
		Rules  []managedRule
	}{c, desired})
	hash := fmt.Sprintf("%x", sha256.Sum256(b))
	fingerprint := filepath.Join(m.runtimeDir, "fingerprint")
	if !force {
		if saved, e := os.ReadFile(fingerprint); e == nil && string(saved) == hash {
			return nil
		}
	}
	if e = m.preflightBackend(c, desired, old); e != nil {
		return e
	}
	if e = writeJSON(m.path("owned.json"), journal); e != nil {
		return e
	}
	if e = m.applyBackend(c, desired, old); e != nil {
		return e
	}
	policy := c.Policy
	if !c.Enabled {
		policy = "allow"
	}
	if e = writeJSON(m.path("owned.json"), ownedBook{Backend: c.Backend, Zone: c.Zone, Rules: desired, Policy: policy}); e != nil {
		return e
	}
	if e = os.MkdirAll(m.runtimeDir, 0700); e != nil {
		return e
	}
	return os.WriteFile(fingerprint, []byte(hash), 0600)
}
func (m *manager) checkReady() error {
	if m.demo {
		return nil
	}
	out, e := m.run("systemctl", "is-enabled", "vpswall-recover.service")
	if e != nil || strings.TrimSpace(out) != "enabled" {
		return errors.New("сначала выполните sudo sh ./install.sh")
	}
	out, e = m.run("systemctl", "is-enabled", "vpswall-worker.timer")
	if e != nil || strings.TrimSpace(out) != "enabled" {
		return errors.New("планировщик не включён; повторите install.sh")
	}
	out, e = m.run("systemctl", "is-active", "vpswall-worker.timer")
	if e != nil || strings.TrimSpace(out) != "active" {
		return errors.New("планировщик не запущен: sudo systemctl start vpswall-worker.timer")
	}
	return nil
}
func (m *manager) pauseWindow(id string) error {
	return m.withLock(func() error {
		windows, e := m.windows()
		if e != nil {
			return e
		}
		found := false
		for i := range windows {
			if windows[i].ID == id {
				windows[i].Paused = !windows[i].Paused
				found = true
			}
		}
		if !found {
			return errors.New("окно не найдено")
		}
		if e = writeJSON(m.path("windows.json"), windows); e != nil {
			return e
		}
		c, e := m.config()
		if e != nil {
			return e
		}
		return m.synchronize(c, true)
	})
}
func (m *manager) saveBackup() (string, error) {
	var id string
	e := m.withLock(func() error {
		c, e := m.config()
		if e != nil {
			return e
		}
		if e = validateConfig(c); e != nil {
			return e
		}
		id, e = newID()
		if e != nil {
			return e
		}
		dir := m.path("managed-backups")
		if e = os.MkdirAll(dir, 0700); e != nil {
			return e
		}
		return writeJSON(filepath.Join(dir, id+".json"), c)
	})
	return id, e
}
func (m *manager) change(description string, after managerConfig) (*managerChange, error) {
	return m.changeSSH(description, after, "")
}
func (m *manager) changeSSH(description string, after managerConfig, sshPort string) (*managerChange, error) {
	var result *managerChange
	e := m.withLock(func() error {
		p, e := m.pending()
		if e != nil {
			return e
		}
		if p != nil {
			return errors.New("сначала подтвердите или отмените ожидающее изменение")
		}
		if e = m.checkReady(); e != nil {
			return e
		}
		before, e := m.config()
		if e != nil {
			return e
		}
		if before.Backend == "" {
			return errors.New("выберите сетевой экран")
		}
		if after.Backend != before.Backend || after.Zone != before.Zone {
			return errors.New("смена backend/зоны — через настройки")
		}
		if e = validateConfig(after); e != nil {
			return e
		}
		if sshPort != "" {
			if e = m.prepareSSH(sshPort); e != nil {
				return e
			}
		}
		token, e := newID()
		if e != nil {
			return e
		}
		p = &managerChange{Token: token, Before: before, SSH: m.ssh, SSHPort: sshPort, Deadline: m.now().Add(120 * time.Second), Description: description}
		if e = writeJSON(m.path("change.json"), p); e != nil {
			return e
		}
		m.run("systemctl", "stop", "vpswall-change.timer", "vpswall-change.service")
		m.run("systemctl", "reset-failed", "vpswall-change.service")
		if _, e = m.run("systemd-run", "--collect", "--unit=vpswall-change", "--on-active=120s", "--timer-property=AccuracySec=1s", "--property=Restart=on-failure", "--property=RestartSec=15s", executable, "rollback"); e != nil {
			os.Remove(m.path("change.json"))
			return e
		}
		timed := *m
		baseRun := m.run
		timed.run = func(name string, args ...string) (string, error) {
			if !m.now().Before(p.Deadline) {
				return "", errors.New("истёк срок применения транзакции")
			}
			return baseRun(name, args...)
		}
		if e = timed.synchronize(after, true); e == nil {
			e = writeJSON(m.path("manager.json"), after)
		}
		if e == nil && sshPort != "" {
			e = timed.startSSH(sshPort)
		}
		if e != nil {
			r := m.rollbackLocked()
			return fmt.Errorf("применение: %v; откат: %v", e, r)
		}
		if !m.now().Before(p.Deadline) {
			return m.rollbackLocked()
		}
		p.Ready = true
		if e = writeJSON(m.path("change.json"), p); e != nil {
			m.rollbackLocked()
			return e
		}
		result = p
		m.log("CHANGE " + description)
		return nil
	})
	return result, e
}
func (m *manager) rollbackLocked() error {
	p, e := m.pending()
	if e != nil || p == nil {
		return e
	}
	if p.SSHPort != "" {
		if e = m.removeSSH(p.SSHPort); e != nil {
			return e
		}
	}
	if e = m.synchronize(p.Before, true); e != nil {
		return e
	}
	if e = writeJSON(m.path("manager.json"), p.Before); e != nil {
		return e
	}
	if e = os.Remove(m.path("change.json")); e != nil {
		return e
	}
	m.run("systemctl", "stop", "vpswall-change.timer")
	m.log("ROLLBACK " + p.Description)
	return nil
}
func (m *manager) rollback() error { return m.withLock(m.rollbackLocked) }
func (m *manager) confirm(token string) error {
	return m.withLock(func() error {
		p, e := m.pending()
		if e != nil {
			return e
		}
		if p == nil {
			return errors.New("нет ожидающего изменения")
		}
		if p.Token != token || !p.Ready {
			return errors.New("неверный код или изменение ещё применяется")
		}
		if !m.now().Before(p.Deadline) {
			return errors.New("срок подтверждения истёк")
		}
		if p.SSH != "" && (m.ssh == "" || m.ssh == p.SSH) {
			return errors.New("подтвердите из нового SSH-подключения")
		}
		if p.SSHPort != "" {
			fields := strings.Fields(m.ssh)
			if len(fields) != 4 || fields[3] != p.SSHPort {
				return errors.New("подтвердите из подключения на новый SSH-порт " + p.SSHPort)
			}
		}
		if e = os.Remove(m.path("change.json")); e != nil {
			return e
		}
		m.run("systemctl", "stop", "vpswall-change.timer")
		m.log("CONFIRM " + p.Description)
		return nil
	})
}
func (m *manager) saveWindow(w window) error {
	return m.withLock(func() error {
		if e := w.validate(); e != nil {
			return e
		}
		if e := m.checkReady(); e != nil {
			return e
		}
		c, e := m.config()
		if e != nil {
			return e
		}
		if !c.Enabled {
			return errors.New("сначала включите выбранный экран")
		}
		windows, e := m.windows()
		if e != nil {
			return e
		}
		for _, v := range windows {
			if v.ID == w.ID {
				return errors.New("ID уже существует")
			}
		}
		windows = append(windows, w)
		if e = writeJSON(m.path("windows.json"), windows); e != nil {
			return e
		}
		m.log("WINDOW ADD " + w.ID)
		return m.synchronize(c, true)
	})
}
func (m *manager) removeWindow(id string) error {
	return m.withLock(func() error {
		if !idPattern.MatchString(id) {
			return errors.New("неверный ID")
		}
		windows, e := m.windows()
		if e != nil {
			return e
		}
		var updated []window
		found := false
		for _, w := range windows {
			if w.ID != id {
				updated = append(updated, w)
			} else {
				found = true
			}
		}
		if !found {
			return errors.New("окно не найдено")
		}
		if e = writeJSON(m.path("windows.json"), updated); e != nil {
			return e
		}
		c, e := m.config()
		if e != nil {
			return e
		}
		return m.synchronize(c, true)
	})
}
func (m *manager) worker(force bool) error {
	return m.withLock(func() error {
		p, e := m.pending()
		if e != nil {
			return e
		}
		if p != nil && !m.now().Before(p.Deadline) {
			if e = m.rollbackLocked(); e != nil {
				return e
			}
		}
		c, e := m.config()
		if e != nil {
			return e
		}
		if c.Backend == "" {
			return nil
		}
		return m.synchronize(c, force)
	})
}
func (m *manager) selectBackend(backend, zone string) error {
	return m.withLock(func() error {
		if !validBackend(backend) || !zonePattern.MatchString(zone) {
			return errors.New("неверный backend/зона")
		}
		p, e := m.pending()
		if e != nil {
			return e
		}
		if p != nil {
			return errors.New("есть неподтверждённое изменение")
		}
		c, e := m.config()
		if e != nil {
			return e
		}
		windows, e := m.windows()
		if e != nil {
			return e
		}
		if c.Backend != "" && (backend != c.Backend || zone != c.Zone) && (len(c.Rules) > 0 || len(windows) > 0 || c.Enabled && (c.Backend == "nftables" || c.Backend == "iptables")) {
			return errors.New("для смены удалите правила/окна VPSWall и отключите старый backend; чужие правила не переносятся автоматически")
		}
		if e = m.conflicts(backend); e != nil {
			return e
		}
		if e = m.installBackend(backend); e != nil {
			return e
		}
		if backend == c.Backend && zone == c.Zone {
			return nil
		}
		active, _ := m.nativeActive(backend)
		c = managerConfig{Backend: backend, Zone: zone, Policy: "allow", Enabled: active}
		if backend == "ufw" {
			out, _ := m.run("ufw", "status", "verbose")
			if strings.Contains(out, "Default: reject") {
				c.Policy = "reject"
			} else if strings.Contains(out, "Default: deny") {
				c.Policy = "deny"
			} else if !active {
				if b, e := os.ReadFile(filepath.Join(m.system, "default", "ufw")); e == nil && strings.Contains(string(b), `DEFAULT_INPUT_POLICY="DROP"`) {
					c.Policy = "deny"
				}
			}
		}
		if e = writeJSON(m.path("manager.json"), c); e != nil {
			return e
		}
		m.log("SELECT " + backend)
		return nil
	})
}
func (m *manager) summary() string {
	c, e := m.config()
	if e != nil {
		return e.Error()
	}
	if c.Backend == "" {
		return "Выберите сетевой экран — VPSWall поможет установить инструмент."
	}
	mode := "ВЫКЛЮЧЕН"
	if c.Enabled {
		mode = "ВКЛЮЧЕН"
	}
	return fmt.Sprintf("%s   •   %s   •   %d правил VPSWall", strings.ToUpper(c.Backend), mode, len(c.Rules))
}
func sortedRules(r []managedRule) []managedRule {
	out := append([]managedRule{}, r...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Temporary != out[j].Temporary {
			return out[i].Temporary
		}
		return out[i].Priority < out[j].Priority
	})
	return out
}
func sshRule(connection string) (managedRule, error) {
	f := strings.Fields(connection)
	if len(f) != 4 {
		return managedRule{}, errors.New("SSH_CONNECTION отсутствует: сначала добавьте разрешение на реальный порт SSH")
	}
	if _, e := netip.ParseAddr(f[0]); e != nil {
		return managedRule{}, e
	}
	r, e := newManaged("allow", "tcp", f[3], f[0], "Текущее SSH-подключение")
	r.AutoSSH = true
	return r, e
}
