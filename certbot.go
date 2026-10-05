package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (m *manager) certbotOpen() error {
	return m.withLock(func() error {
		if e := m.checkReady(); e != nil {
			return e
		}
		c, e := m.config()
		if e != nil {
			return e
		}
		if !c.Enabled {
			return errors.New("выбранный firewall выключен")
		}
		windows, e := m.windows()
		if e != nil {
			return e
		}
		for _, w := range windows {
			if w.Purpose == "certbot" {
				if _, _, active := w.interval(m.now()); active {
					return m.synchronize(c, true)
				}
			}
		}
		r, e := newManaged("allow", "tcp", "80", "any", "Certbot HTTP-01")
		if e != nil {
			return e
		}
		r.Temporary = true
		w := window{ID: r.ID, Rule: r, Kind: "lease", Start: m.now(), Seconds: 3600, Purpose: "certbot"}
		windows = append(windows, w)
		if e = writeJSON(m.path("windows.json"), windows); e != nil {
			return e
		}
		m.log("CERTBOT OPEN " + w.ID)
		return m.synchronize(c, true)
	})
}
func (m *manager) certbotClose() error {
	return m.withLock(func() error {
		windows, e := m.windows()
		if e != nil {
			return e
		}
		var kept []window
		for _, w := range windows {
			if w.Purpose != "certbot" {
				kept = append(kept, w)
			}
		}
		if e = writeJSON(m.path("windows.json"), kept); e != nil {
			return e
		}
		c, e := m.config()
		if e != nil {
			return e
		}
		m.log("CERTBOT CLOSE")
		return m.synchronize(c, true)
	})
}
func (m *manager) installCertbotHooks() error {
	if !m.demo {
		if _, e := binary("certbot"); e != nil {
			return errors.New("Certbot не найден. Установите его привычным способом, затем повторите")
		}
	}
	c, e := m.config()
	if e != nil {
		return e
	}
	if !c.Enabled {
		return errors.New("сначала включите выбранный firewall")
	}
	for _, kind := range []string{"pre", "post"} {
		dir := filepath.Join(m.system, "letsencrypt", "renewal-hooks", kind)
		if e = os.MkdirAll(dir, 0755); e != nil {
			return e
		}
		operation := "certbot-open"
		if kind == "post" {
			operation = "certbot-close"
		}
		path := filepath.Join(dir, "50-vpswall")
		text := "#!/bin/sh\n# Managed by VPSWall\nexec /usr/local/bin/vpswall " + operation + "\n"
		if b, e := os.ReadFile(path); e == nil && !strings.Contains(string(b), "# Managed by VPSWall") {
			return errors.New("имя хука 50-vpswall уже занято")
		}
		if e = os.WriteFile(path, []byte(text), 0755); e != nil {
			return e
		}
		if e = os.Chmod(path, 0755); e != nil {
			return e
		}
	}
	m.log("CERTBOT HOOKS INSTALLED")
	return nil
}
func (m *manager) certbotTimer(clock, zone string) error {
	if _, _, e := clockParts(clock); e != nil {
		return e
	}
	if _, e := time.LoadLocation(zone); e != nil {
		return e
	}
	if e := m.installCertbotHooks(); e != nil {
		return e
	}
	path := "/usr/bin/certbot"
	if !m.demo {
		var e error
		path, e = binary("certbot")
		if e != nil {
			return e
		}
	}
	dir := filepath.Join(m.system, "systemd", "system")
	if e := os.MkdirAll(dir, 0755); e != nil {
		return e
	}
	files := map[string]string{
		"vpswall-certbot.service": "[Unit]\nDescription=VPSWall scheduled Certbot renewal\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=oneshot\nExecStart=" + path + " renew --quiet\n",
		"vpswall-certbot.timer":   fmt.Sprintf("[Unit]\nDescription=VPSWall daily Certbot renewal\n[Timer]\nOnCalendar=*-*-* %s:00 %s\nPersistent=true\nAccuracySec=1s\nUnit=vpswall-certbot.service\n[Install]\nWantedBy=timers.target\n", clock, zone),
	}
	for name, text := range files {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(text), 0644); e != nil {
			return e
		}
	}
	if !m.demo {
		if _, e := m.run("systemctl", "daemon-reload"); e != nil {
			return e
		}
		if _, e := m.run("systemctl", "enable", "--now", "vpswall-certbot.timer"); e != nil {
			return e
		}
		// Avoid a second distribution-managed timer; preserve its previous state for removal.
		original := map[string]string{}
		if e := readJSON(m.path("certbot-original-timers.json"), &original); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if original == nil {
			original = map[string]string{}
		}
		var toDisable []string
		for _, name := range []string{"certbot.timer", "snap.certbot.renew.timer"} {
			out, e := m.run("systemctl", "is-enabled", name)
			if e == nil && strings.TrimSpace(out) == "enabled" {
				original[name] = "enabled"
				toDisable = append(toDisable, name)
			}
		}
		if len(original) > 0 {
			if e := writeJSON(m.path("certbot-original-timers.json"), original); e != nil {
				return e
			}
		}
		for _, name := range toDisable {
			if _, e := m.run("systemctl", "disable", "--now", name); e != nil {
				return e
			}
		}
	}
	m.log("CERTBOT TIMER " + clock + " " + zone)
	return nil
}
func (m *manager) removeCertbotIntegration() error {
	if e := m.certbotClose(); e != nil {
		return e
	}
	if !m.demo {
		m.run("systemctl", "disable", "--now", "vpswall-certbot.timer")
	}
	for _, kind := range []string{"pre", "post"} {
		path := filepath.Join(m.system, "letsencrypt", "renewal-hooks", kind, "50-vpswall")
		b, e := os.ReadFile(path)
		if e == nil && strings.Contains(string(b), "# Managed by VPSWall") {
			if e = os.Remove(path); e != nil {
				return e
			}
		}
	}
	for _, name := range []string{"vpswall-certbot.service", "vpswall-certbot.timer"} {
		path := filepath.Join(m.system, "systemd", "system", name)
		if e := os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	if !m.demo {
		m.run("systemctl", "daemon-reload")
		var original map[string]string
		if readJSON(m.path("certbot-original-timers.json"), &original) == nil {
			for name, state := range original {
				if state == "enabled" && (name == "certbot.timer" || name == "snap.certbot.renew.timer") {
					if _, e := m.run("systemctl", "enable", "--now", name); e != nil {
						return e
					}
				}
			}
			os.Remove(m.path("certbot-original-timers.json"))
		}
	}
	return nil
}
