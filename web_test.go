package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func webFixture(t *testing.T) (*webServer, string) {
	t.Helper()
	m := managerFixture(t)
	token, e := m.issueWebToken()
	if e != nil {
		t.Fatal(e)
	}
	return &webServer{m: m}, token
}
func webRequest(s *webServer, token, method, path, body, origin, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	r.Host = host
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func waitWebJob(t *testing.T, s *webServer) webJob {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		job := s.job
		s.mu.Unlock()
		if !job.Running {
			return job
		}
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatal("job timed out")
	return webJob{}
}
func TestWebAuthenticationOriginAndHost(t *testing.T) {
	s, token := webFixture(t)
	s.m.demo = false
	cases := []struct {
		token, method, path, body, origin, host string
		status                                  int
	}{
		{"", "GET", "/api/state", "", "", "127.0.0.1:8090", 401},
		{token, "GET", "/api/state", "", "", "127.0.0.1:18090", 200},
		{token, "GET", "/api/state", "", "", "evil.example:8090", 403},
		{token, "POST", "/api/action", `{"op":"backup"}`, "http://evil.example", "127.0.0.1:8090", 403},
		{token, "POST", "/api/action", `{"op":"backup"}`, "", "127.0.0.1:8090", 403},
		{token, "POST", "/api/action", `{"op":"backup","command":"rm"}`, "http://127.0.0.1:8090", "127.0.0.1:8090", 400},
		{token, "GET", "/api/diagnostics?kind=arbitrary", "", "", "127.0.0.1:8090", 400},
		{token, "GET", "/", "", "", "127.0.0.1:8090", 200},
	}
	for _, c := range cases {
		w := webRequest(s, c.token, c.method, c.path, c.body, c.origin, c.host)
		if w.Code != c.status {
			t.Fatalf("%s %s: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("CSP missing")
		}
	}
	demo := webRequest(s, "", "GET", "/api/demo", "", "", "127.0.0.1:8090")
	if strings.Contains(demo.Body.String(), "token") {
		t.Fatal("production disclosed demo token")
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:8090/", nil)
	r.RemoteAddr = "192.0.2.1:5000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("nonlocal accepted")
	}
}
func TestWebTokenRotationExpiryAndNoSecretInState(t *testing.T) {
	s, old := webFixture(t)
	s.m.demo = false
	token, e := s.m.issueWebToken()
	if e != nil {
		t.Fatal(e)
	}
	if webRequest(s, old, "GET", "/api/job", "", "", "127.0.0.1:8090").Code != 401 {
		t.Fatal("old token retained")
	}
	w := webRequest(s, token, "GET", "/api/state", "", "", "127.0.0.1:8090")
	if w.Code != 200 || strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), tokenHash(token)) {
		t.Fatal("token leaked", w.Code)
	}
	s.m.now = func() time.Time { return time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC) }
	if webRequest(s, token, "GET", "/api/state", "", "", "127.0.0.1:8090").Code != 401 {
		t.Fatal("expired accepted")
	}
}
func TestWebRuleTransactionCASAndHTTPConfirmationDenied(t *testing.T) {
	s, token := webFixture(t)
	c, _ := s.m.config()
	revision := configRevision(c)
	body := `{"op":"rule-save","revision":"` + revision + `","action":"allow","protocol":"tcp","port":"8443","source":"any","priority":100,"comment":"API"}`
	w := webRequest(s, token, "POST", "/api/action", body, "http://127.0.0.1:8090", "127.0.0.1:8090")
	if w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	job := waitWebJob(t, s)
	if job.Error != "" || job.Pending == nil {
		t.Fatal(job)
	}
	c, _ = s.m.config()
	if len(c.Rules) != 1 || c.Rules[0].Port != "8443" {
		t.Fatal(c)
	}
	// Production cannot use a browser action to bypass a new SSH connection.
	s.m.demo = false
	_, _, e := s.action(s.m, webAction{Op: "demo-confirm"})
	if e == nil {
		t.Fatal("HTTP confirmation accepted")
	}
	s.m.demo = true
	s.m.rollback()
	c, _ = s.m.config()
	c.Policy = "allow"
	writeJSON(s.m.path("manager.json"), c)
	w = webRequest(s, token, "POST", "/api/action", body, "http://127.0.0.1:8090", "127.0.0.1:8090")
	if w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	job = waitWebJob(t, s)
	if !strings.Contains(job.Error, "другом сеансе") {
		t.Fatal("stale overwrite", job)
	}
}
func TestWebLimitsBusyAndWindowPersistence(t *testing.T) {
	s, token := webFixture(t)
	s.mu.Lock()
	s.job = webJob{Running: true}
	s.mu.Unlock()
	if webRequest(s, token, "POST", "/api/action", `{"op":"backup"}`, "http://127.0.0.1:8090", "127.0.0.1:8090").Code != 409 {
		t.Fatal("concurrent accepted")
	}
	s.mu.Lock()
	s.job.Running = false
	s.mu.Unlock()
	huge := `{"op":"backup","comment":"` + strings.Repeat("x", 40000) + `"}`
	if webRequest(s, token, "POST", "/api/action", huge, "http://127.0.0.1:8090", "127.0.0.1:8090").Code != 400 {
		t.Fatal("large body accepted")
	}
	_, _, e := s.action(s.m, webAction{Op: "window-add", Protocol: "tcp", Port: "80", Source: "any", Kind: "daily", Clock: "03:00", Zone: "Europe/Moscow", Duration: "1h"})
	if e != nil {
		t.Fatal(e)
	}
	state, e := s.state(s.m)
	if e != nil || len(state.Windows) != 1 || state.Windows[0].Zone != "Europe/Moscow" {
		t.Fatal(state, e)
	}
	if _, _, e = s.action(s.m, webAction{Op: "restore", ID: "../../web-auth"}); e == nil {
		t.Fatal("path traversal")
	}
}
func TestWebServiceScopedAndDisabledOnInstall(t *testing.T) {
	m := managerFixture(t)
	if e := m.webService(true); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(m.system, "systemd", "system", "vpswall-web.service")
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "vpswall web serve") || strings.Contains(string(data), "0.0.0.0") {
		t.Fatal(string(data))
	}
	m.issueWebToken()
	if e := m.webService(false); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(m.path("web-auth.json")); !os.IsNotExist(e) {
		t.Fatal("token retained")
	}
	os.WriteFile(path, []byte("foreign"), 0644)
	if e := m.webService(true); e == nil {
		t.Fatal("foreign overwritten")
	}
}
func TestWebLoopbackListener(t *testing.T) {
	s, token := webFixture(t)
	server := httptest.NewServer(s)
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL+"/api/state", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	var state webState
	if e = json.Unmarshal(data, &state); e != nil || response.StatusCode != 200 || !state.Demo {
		t.Fatal(string(data), e)
	}
}
