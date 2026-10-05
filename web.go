package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html web/app.js web/style.css
var webAssets embed.FS

type webAuth struct {
	Hash    string    `json:"hash"`
	SSH     string    `json:"ssh"`
	Expires time.Time `json:"expires"`
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func configRevision(c managerConfig) string {
	data, _ := json.Marshal(c)
	return tokenHash(string(data))
}
func (m *manager) issueWebToken() (string, error) {
	if _, e := sshRule(m.ssh); e != nil {
		return "", e
	}
	bytes := make([]byte, 32)
	if _, e := rand.Read(bytes); e != nil {
		return "", e
	}
	token := base64.RawURLEncoding.EncodeToString(bytes)
	if m.demo {
		token = "vpswall-demo"
	}
	e := writeJSON(m.path("web-auth.json"), webAuth{tokenHash(token), m.ssh, m.now().Add(8 * time.Hour)})
	return token, e
}

const webUnitMarker = "# Managed by VPSWall web\n"

func (m *manager) webService(enable bool) error {
	unit := filepath.Join(m.system, "systemd", "system", "vpswall-web.service")
	if enable {
		if e := m.checkReady(); e != nil {
			return e
		}
		if b, e := os.ReadFile(unit); e == nil && !strings.HasPrefix(string(b), webUnitMarker) {
			return errors.New("имя vpswall-web.service занято чужим unit")
		}
		body := webUnitMarker + `[Unit]
Description=VPSWall localhost web panel
After=vpswall-recover.service network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/vpswall web serve
Restart=on-failure
RestartSec=5s
UMask=0077
[Install]
WantedBy=multi-user.target
`
		if e := os.MkdirAll(filepath.Dir(unit), 0755); e != nil {
			return e
		}
		if e := os.WriteFile(unit, []byte(body), 0644); e != nil {
			return e
		}
		if _, e := m.run("systemctl", "daemon-reload"); e != nil {
			return e
		}
		_, e := m.run("systemctl", "enable", "--now", "vpswall-web.service")
		return e
	}
	b, e := os.ReadFile(unit)
	if e != nil {
		return e
	}
	if !strings.HasPrefix(string(b), webUnitMarker) {
		return errors.New("отказ отключения чужого unit")
	}
	if _, e = m.run("systemctl", "disable", "--now", "vpswall-web.service"); e != nil {
		return e
	}
	if e = os.Remove(m.path("web-auth.json")); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}

type webJob struct {
	ID      string      `json:"id"`
	Running bool        `json:"running"`
	Message string      `json:"message"`
	Error   string      `json:"error,omitempty"`
	Pending *webPending `json:"pending,omitempty"`
}
type webPending struct {
	Token       string    `json:"token"`
	Deadline    time.Time `json:"deadline"`
	Description string    `json:"description"`
	SSHPort     string    `json:"ssh_port,omitempty"`
}

func publicPending(p *managerChange) *webPending {
	if p == nil {
		return nil
	}
	return &webPending{p.Token, p.Deadline, p.Description, p.SSHPort}
}

type webServer struct {
	m   *manager
	mu  sync.Mutex
	job webJob
}

func webJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func webError(w http.ResponseWriter, status int, e error) {
	webJSON(w, status, map[string]string{"error": e.Error()})
}
func localhostHost(host string) bool {
	h, p, e := net.SplitHostPort(host)
	if e != nil {
		return false
	}
	n, e := strconv.Atoi(p)
	if e != nil || n < 1 || n > 65535 {
		return false
	}
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}
func (s *webServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if e != nil || ip == nil || !ip.IsLoopback() || !localhostHost(r.Host) {
		webError(w, 403, errors.New("только локальный доступ"))
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" && origin != "http://"+r.Host || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		webError(w, 403, errors.New("неверный источник запроса"))
		return
	}
	if r.Method == http.MethodOptions {
		webError(w, 405, errors.New("CORS не разрешён"))
		return
	}
	if r.URL.Path == "/api/demo" && r.Method == http.MethodGet {
		data := map[string]any{"demo": s.m.demo}
		if s.m.demo {
			data["token"] = "vpswall-demo"
		}
		webJSON(w, 200, data)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		file := ""
		contentType := ""
		switch r.URL.Path {
		case "/":
			file = "web/index.html"
			contentType = "text/html; charset=utf-8"
		case "/app.js":
			file = "web/app.js"
			contentType = "text/javascript; charset=utf-8"
		case "/style.css":
			file = "web/style.css"
			contentType = "text/css; charset=utf-8"
		default:
			http.NotFound(w, r)
			return
		}
		data, e := webAssets.ReadFile(file)
		if e != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(data)
		return
	}
	var auth webAuth
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if e := readJSON(s.m.path("web-auth.json"), &auth); e != nil || !s.m.now().Before(auth.Expires) || len(auth.Hash) != 64 || subtle.ConstantTimeCompare([]byte(tokenHash(token)), []byte(auth.Hash)) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		webError(w, 401, errors.New("токен отсутствует, истёк или был заменён; получите web token из SSH"))
		return
	}
	m := *s.m
	m.ssh = auth.SSH
	if _, e := sshRule(m.ssh); e != nil {
		webError(w, 401, e)
		return
	}
	switch {
	case r.URL.Path == "/api/state" && r.Method == http.MethodGet:
		s.mu.Lock()
		busy := s.job.Running
		s.mu.Unlock()
		if busy {
			webError(w, 409, errors.New("операция выполняется; дождитесь результата"))
			return
		}
		state, e := s.state(&m)
		if e != nil {
			webError(w, 500, e)
			return
		}
		webJSON(w, 200, state)
	case r.URL.Path == "/api/job" && r.Method == http.MethodGet:
		s.mu.Lock()
		job := s.job
		s.mu.Unlock()
		webJSON(w, 200, job)
	case r.URL.Path == "/api/diagnostics" && r.Method == http.MethodGet:
		kind := r.URL.Query().Get("kind")
		var out string
		var e error
		switch kind {
		case "rules":
			c, err := m.config()
			if err != nil {
				e = err
			} else {
				out, e = m.rawStatus(c)
			}
		case "ports":
			out, e = m.run("ss", "-lntup")
		case "worker":
			out, e = m.run("journalctl", "-u", "vpswall-worker.service", "-u", "vpswall-recover.service", "-n", "80", "--no-pager")
		case "certbot":
			out, e = m.run("systemctl", "status", "vpswall-certbot.timer", "vpswall-certbot.service", "--no-pager")
		default:
			webError(w, 400, errors.New("неизвестная диагностика"))
			return
		}
		// status may return nonzero for inactive units; include the actual output.
		if e != nil && out == "" {
			webError(w, 400, e)
			return
		}
		webJSON(w, 200, map[string]string{"output": out})
	case r.URL.Path == "/api/action" && r.Method == http.MethodPost:
		if origin != "http://"+r.Host {
			webError(w, 403, errors.New("Origin обязателен для изменения"))
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			webError(w, 415, errors.New("требуется application/json"))
			return
		}
		var request webAction
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768))
		decoder.DisallowUnknownFields()
		if e := decoder.Decode(&request); e != nil {
			webError(w, 400, e)
			return
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			webError(w, 400, errors.New("лишние данные запроса"))
			return
		}
		s.mu.Lock()
		if s.job.Running {
			s.mu.Unlock()
			webError(w, 409, errors.New("другая операция ещё выполняется"))
			return
		}
		id, e := newID()
		if e != nil {
			s.mu.Unlock()
			webError(w, 500, e)
			return
		}
		s.job = webJob{ID: id, Running: true, Message: "Операция выполняется"}
		job := s.job
		s.mu.Unlock()
		go func() {
			message, p, e := s.action(&m, request)
			s.mu.Lock()
			defer s.mu.Unlock()
			s.job.Running = false
			s.job.Message = message
			s.job.Pending = publicPending(p)
			if e != nil {
				s.job.Error = e.Error()
			}
		}()
		webJSON(w, 202, job)
	default:
		webError(w, 404, errors.New("операция не найдена"))
	}
}

type webWindow struct {
	window
	Active bool      `json:"active"`
	End    time.Time `json:"end"`
	Next   time.Time `json:"next"`
}
type webState struct {
	Config   managerConfig `json:"config"`
	Revision string        `json:"revision"`
	Windows  []webWindow   `json:"windows"`
	Pending  *webPending   `json:"pending"`
	Demo     bool          `json:"demo"`
	Host     string        `json:"host"`
	Version  string        `json:"version"`
	SSHPort  string        `json:"ssh_port"`
	Backups  []string      `json:"backups"`
	History  string        `json:"history"`
	Certbot  bool          `json:"certbot"`
	CertTime string        `json:"cert_time"`
	Now      time.Time     `json:"now"`
}

func tailFile(path string) string {
	f, e := os.Open(path)
	if e != nil {
		return ""
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return ""
	}
	if st.Size() > 65536 {
		f.Seek(st.Size()-65536, io.SeekStart)
	}
	data, _ := io.ReadAll(io.LimitReader(f, 65536))
	return string(data)
}
func (s *webServer) state(m *manager) (webState, error) {
	out := webState{Demo: m.demo, Host: hostname(), Version: version, Now: m.now(), Windows: []webWindow{}, Backups: []string{}}
	if m.demo {
		out.Host = "demo-vps"
	}
	e := m.withLock(func() error {
		c, e := m.config()
		if e != nil {
			return e
		}
		out.Config = c
		out.Revision = configRevision(c)
		p, e := m.pending()
		if e != nil {
			return e
		}
		out.Pending = publicPending(p)
		windows, e := m.windows()
		if e != nil {
			return e
		}
		for _, w := range windows {
			_, end, active := w.interval(m.now())
			out.Windows = append(out.Windows, webWindow{w, active, end, w.next(m.now())})
		}
		return nil
	})
	if e != nil {
		return out, e
	}
	if r, e := sshRule(m.ssh); e == nil {
		out.SSHPort = r.Port
	}
	entries, _ := os.ReadDir(m.path("managed-backups"))
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if strings.HasSuffix(entry.Name(), ".json") && idPattern.MatchString(id) {
			out.Backups = append(out.Backups, id)
		}
	}
	out.History = tailFile(m.path("history.log"))
	hook, e := os.ReadFile(filepath.Join(m.system, "letsencrypt", "renewal-hooks", "pre", "50-vpswall"))
	out.Certbot = e == nil && strings.Contains(string(hook), "# Managed by VPSWall")
	timer, _ := os.ReadFile(filepath.Join(m.system, "systemd", "system", "vpswall-certbot.timer"))
	for _, line := range strings.Split(string(timer), "\n") {
		if strings.HasPrefix(line, "OnCalendar=*-*-* ") {
			out.CertTime = strings.TrimPrefix(line, "OnCalendar=*-*-* ")
		}
	}
	return out, nil
}

type webAction struct {
	Op       string `json:"op"`
	Revision string `json:"revision"`
	ID       string `json:"id"`
	Action   string `json:"action"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Source   string `json:"source"`
	Comment  string `json:"comment"`
	Priority int    `json:"priority"`
	Kind     string `json:"kind"`
	Clock    string `json:"clock"`
	Zone     string `json:"zone"`
	Duration string `json:"duration"`
	Start    string `json:"start"`
	Backend  string `json:"backend"`
	Policy   string `json:"policy"`
	Enabled  bool   `json:"enabled"`
}

func (s *webServer) action(m *manager, a webAction) (string, *managerChange, error) {
	legacy := &app{state: m.root}
	if p, e := legacy.getPending(); e != nil {
		return "", nil, e
	} else if p != nil {
		return "", nil, errors.New("сначала завершите транзакцию версии 0.1 из терминала")
	}
	c, e := m.config()
	if e != nil {
		return "", nil, e
	}
	if p, e := m.pending(); e != nil {
		return "", nil, e
	} else if p != nil && a.Op != "rollback" && !(a.Op == "demo-confirm" && m.demo) {
		return "", nil, errors.New("сначала подтвердите из нового SSH или отмените ожидающее изменение")
	}
	change := func(description string, after managerConfig, port string) (string, *managerChange, error) {
		if a.Revision == "" {
			return "", nil, errors.New("обновите страницу перед изменением")
		}
		p, e := m.changeChecked(description, after, port, a.Revision)
		return "Изменение применено. Подтвердите из нового SSH за 120 секунд.", p, e
	}
	switch a.Op {
	case "demo-confirm":
		if !m.demo {
			return "", nil, errors.New("подтверждение доступно только из нового SSH")
		}
		p, e := m.pending()
		if e != nil || p == nil {
			return "", nil, errors.New("нет ожидающего изменения")
		}
		fields := strings.Fields(m.ssh)
		fields[1] = "65530"
		if p.SSHPort != "" {
			fields[3] = p.SSHPort
		}
		m.ssh = strings.Join(fields, " ")
		return "Демонстрационное подтверждение; в рабочем режиме нужен новый SSH", nil, m.confirm(p.Token)
	case "rule-save":
		r, e := newManaged(a.Action, a.Protocol, a.Port, a.Source, a.Comment)
		if e != nil {
			return "", nil, e
		}
		r.Priority = a.Priority
		if e = r.validate(); e != nil {
			return "", nil, e
		}
		found := false
		for i, old := range c.Rules {
			if old.ID == a.ID {
				c.Rules[i] = r
				found = true
			}
		}
		if a.ID != "" && !found {
			return "", nil, errors.New("правило уже удалено")
		}
		if !found {
			c.Rules = append(c.Rules, r)
		}
		return change("Веб: "+r.Action+" "+r.Port+"/"+r.Protocol, c, "")
	case "rule-delete":
		kept := []managedRule{}
		found := false
		for _, r := range c.Rules {
			if r.ID == a.ID {
				found = true
			} else {
				kept = append(kept, r)
			}
		}
		if !found {
			return "", nil, errors.New("правило не найдено")
		}
		c.Rules = kept
		return change("Веб: удалить правило "+a.ID, c, "")
	case "toggle":
		c.Enabled = a.Enabled
		if c.Enabled {
			c, e = keepSSH(c, m.ssh)
			if e != nil {
				return "", nil, e
			}
		}
		return change("Веб: состояние firewall; текущий SSH сохраняется при включении", c, "")
	case "ssh-new":
		c, e = keepSSH(c, m.ssh)
		if e != nil {
			return "", nil, e
		}
		old, _ := sshRule(m.ssh)
		r, e := newManaged("allow", "tcp", a.Port, old.Source, "SSH · новый порт")
		if e != nil {
			return "", nil, e
		}
		r.Priority = 0
		r.AutoSSH = true
		c.Enabled = true
		c.Rules = append(c.Rules, r)
		return change("Веб: новый SSH-порт "+a.Port+"; старый сохраняется", c, a.Port)
	case "policy":
		c.Policy = a.Policy
		return change("Веб: политика входящих "+a.Policy, c, "")
	case "restore":
		if !idPattern.MatchString(a.ID) {
			return "", nil, errors.New("неверный ID копии")
		}
		var saved managerConfig
		if e = readJSON(m.path("managed-backups/"+a.ID+".json"), &saved); e != nil {
			return "", nil, e
		}
		return change("Веб: восстановление копии "+a.ID, saved, "")
	case "rollback":
		return "Изменение отменено", nil, m.rollback()
	case "window-add":
		r, e := newManaged("allow", a.Protocol, a.Port, a.Source, "Временное окно")
		if e != nil {
			return "", nil, e
		}
		duration, e := time.ParseDuration(a.Duration)
		if e != nil {
			return "", nil, e
		}
		w := window{ID: r.ID, Rule: r, Kind: a.Kind, Clock: a.Clock, Zone: a.Zone, Seconds: int64(duration / time.Second), Start: m.now()}
		if a.Kind == "once" {
			loc, e := time.LoadLocation(a.Zone)
			if e != nil {
				return "", nil, e
			}
			w.Start, e = time.ParseInLocation("2006-01-02 15:04", a.Start, loc)
			if e != nil {
				return "", nil, e
			}
			if !w.Start.After(m.now()) {
				return "", nil, errors.New("начало должно быть в будущем")
			}
		}
		if e = w.validate(); e != nil {
			return "", nil, e
		}
		return "Окно сохранено", nil, m.saveWindow(w)
	case "window-pause":
		return "Состояние окна изменено", nil, m.pauseWindow(a.ID)
	case "window-delete":
		return "Окно удалено", nil, m.removeWindow(a.ID)
	case "backend":
		return "Сетевой экран выбран", nil, m.selectBackend(a.Backend, a.Zone)
	case "backup":
		id, e := m.saveBackup()
		return "Копия сохранена: " + id, nil, e
	case "cert-hooks":
		return "Хуки Certbot подключены", nil, m.installCertbotHooks()
	case "cert-time":
		return "Расписание Certbot сохранено", nil, m.certbotTimer(a.Clock, a.Zone)
	case "cert-remove":
		return "Интеграция Certbot отключена", nil, m.removeCertbotIntegration()
	case "cert-test":
		out, e := m.run("certbot", "renew", "--dry-run")
		return out, nil, e
	default:
		return "", nil, errors.New("неизвестная операция")
	}
}
func (m *manager) serveWeb(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("неверный порт")
	}
	listener, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if e != nil {
		return e
	}
	fmt.Printf("VPSWall web: http://127.0.0.1:%d · только localhost\n", port)
	server := &http.Server{Handler: &webServer{m: m}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	return server.Serve(listener)
}
