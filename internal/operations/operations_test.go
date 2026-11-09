package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	audit "github.com/soulteary/audit-kit/v2"
	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/gateway"
	"github.com/soulteary/porter/internal/observe"
	"github.com/soulteary/porter/internal/provider"
	"github.com/soulteary/porter/internal/store"
	version "github.com/soulteary/version-kit/v4"
)

type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *logBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func configuration(t *testing.T) config.Config {
	t.Helper()
	c := config.Config{PublicURL: "https://porter.test", LandingURL: "https://porter.test/app", Database: filepath.Join(t.TempDir(), "porter.db"), ProxyKey: strings.Repeat("p", 32), Providers: map[string]config.Provider{"github": {ClientID: "app", ClientSecret: "SECRET"}}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	return c
}
func admin(r *Runtime, c config.Config, path, peer, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "http://management.test"+path, nil)
	req.RemoteAddr = peer
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	w := httptest.NewRecorder()
	r.Handler(c, version.New("v0.1.0", "abc123", "2026-11-10T00:00:00Z")).ServeHTTP(w, req)
	return w
}
func TestManagementIsolationAndReadiness(t *testing.T) {
	c := configuration(t)
	var unavailable atomic.Bool
	r, e := New(c, func(context.Context) error {
		if unavailable.Load() {
			return errors.New("SECRET storage path")
		}
		return nil
	}, version.New("dev", "test", "unknown"), &logBuffer{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	for _, path := range []string{"/readyz", "/metrics", "/version"} {
		if w := admin(r, c, path, "203.0.113.1:1000", ""); w.Code != 403 {
			t.Fatal("forwarded IP granted management access", w.Code)
		}
	}
	if w := admin(r, c, "/auth", "127.0.0.1:1000", ""); w.Code != 404 {
		t.Fatal("authentication exposed on management listener")
	}
	if w := admin(r, c, "/readyz", "127.0.0.1:1000", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	unavailable.Store(true)
	w := admin(r, c, "/readyz", "127.0.0.1:1000", "")
	if w.Code != 503 || strings.Contains(w.Body.String(), "SECRET") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := admin(r, c, "/healthz", "127.0.0.1:1000", ""); w.Code != 200 {
		t.Fatal("dependency failure changed liveness")
	}
	unavailable.Store(false)
	r.Maintenance(errors.New("SECRET"))
	if w := admin(r, c, "/readyz", "127.0.0.1:1000", ""); w.Code != 503 {
		t.Fatal("maintenance failure not reflected")
	}
	r.Maintenance(nil)
	r.Drain()
	if w := admin(r, c, "/readyz", "127.0.0.1:1000", ""); w.Code != 503 {
		t.Fatal("draining service remained ready")
	}
	c.Operations.Key = strings.Repeat("m", 32)
	if w := admin(r, c, "/version", "127.0.0.1:1000", c.ProxyKey); w.Code != 401 {
		t.Fatal("proxy credential granted management access")
	}
	if w := admin(r, c, "/version", "203.0.113.1:1000", c.Operations.Key); w.Code != 200 || !strings.Contains(w.Body.String(), "abc123") {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestAuditFlushAndRedaction(t *testing.T) {
	c := configuration(t)
	logs := &logBuffer{}
	r, e := New(c, func(context.Context) error { return nil }, version.New("dev", "test", "unknown"), logs)
	if e != nil {
		t.Fatal(e)
	}
	handler := observe.Wrap(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { http.Error(w, "SECRET upstream body", 400) }), r)
	req := httptest.NewRequest("GET", "https://porter.test/callback/github?code=SECRET&state=SECRET", nil)
	req.Header.Set("X-Request-ID", "SECRET")
	req.Header.Set("Cookie", "SECRET")
	req.Header.Set("Authorization", "SECRET")
	req.Header.Set("User-Agent", "SECRET")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 400 || w.Body.String() != "SECRET upstream body\n" {
		t.Fatal("observation changed response")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(c.Operations.AuditFile)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(data)+logs.String(), "SECRET") {
		t.Fatal("sensitive request data persisted")
	}
	var record audit.Record
	if e = json.Unmarshal(bytes.TrimSpace(data), &record); e != nil {
		t.Fatal(e)
	}
	if record.EventType != audit.EventLoginFailed || record.Provider != "github" || len(record.RequestID) != 32 {
		t.Fatal(record)
	}
	st, _ := os.Stat(c.Operations.AuditFile)
	if st.Mode().Perm() != 0600 {
		t.Fatal("audit file is not private")
	}
}

type controlledStorage struct {
	entered, release chan struct{}
	fail             bool
	once             sync.Once
	writes           atomic.Int32
}

func (s *controlledStorage) Write(context.Context, *audit.Record) error {
	if s.entered != nil {
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	s.writes.Add(1)
	if s.fail {
		return errors.New("SECRET backing storage")
	}
	return nil
}
func (*controlledStorage) Query(context.Context, *audit.QueryFilter) ([]*audit.Record, error) {
	return nil, nil
}
func (*controlledStorage) Close() error { return nil }
func TestAuditQueueAndWriteFailureMetrics(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "queue full", true: "write failed"}[fail], func(t *testing.T) {
			c := configuration(t)
			c.Operations.AuditQueueSize = 1
			sink := &controlledStorage{fail: fail}
			if !fail {
				sink.entered = make(chan struct{})
				sink.release = make(chan struct{})
			}
			r := newRuntime(c, func(context.Context) error { return nil }, version.New("dev", "test", "unknown"), &logBuffer{}, sink)
			event := observe.Event{Action: "login_start", Route: "/login/{provider}", Method: "POST", Provider: "github", Result: "success", Reason: "ok", RequestID: "request", Status: 200}
			r.Observe(context.Background(), event)
			if !fail {
				select {
				case <-sink.entered:
				case <-time.After(time.Second):
					t.Fatal("writer did not start")
				}
				r.Observe(context.Background(), event)
				r.Observe(context.Background(), event)
				close(sink.release)
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			body := admin(r, c, "/metrics", "127.0.0.1:1000", "").Body.String()
			expected := "porter_audit_dropped_total 1"
			if fail {
				expected = "porter_audit_write_failures_total 1"
			}
			if !strings.Contains(body, expected) || strings.Contains(body, "SECRET") {
				t.Fatal("missing or unsafe loss metric", body)
			}
		})
	}
}
func TestStargateProbeDoesNotAuthenticateOrFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer sink.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Stargate-Header-Auth") != "" || r.Header.Get("Cookie") != "" {
			t.Error("probe crossed authentication boundary")
		}
		http.Redirect(w, r, sink.URL, 302)
	}))
	defer upstream.Close()
	if e := CheckStargate(context.Background(), upstream.URL+"/_auth", time.Second); e == nil || hits.Load() != 0 {
		t.Fatal("readiness followed redirect")
	}
}
func TestBlockedStorageProbeIsBounded(t *testing.T) {
	c := configuration(t)
	c.Operations.ProbeTimeoutSeconds = 1
	release := make(chan struct{})
	var entered atomic.Int32
	r, e := New(c, func(context.Context) error { entered.Add(1); <-release; return nil }, version.New("dev", "test", "unknown"), &logBuffer{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer close(release)
	start := time.Now()
	if w := admin(r, c, "/readyz", "127.0.0.1:1000", ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("probe ignored deadline")
	}
	if w := admin(r, c, "/readyz", "127.0.0.1:1000", ""); w.Code != 503 || entered.Load() != 1 {
		t.Fatal("blocked probes accumulated", entered.Load())
	}
}
func TestAuditRefusesPublicFilesAndDatabaseAliases(t *testing.T) {
	c := configuration(t)
	if e := os.WriteFile(c.Database, []byte("session database"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(c.Database, c.Operations.AuditFile); e != nil {
		t.Fatal(e)
	}
	if _, e := New(c, func(context.Context) error { return nil }, version.New("dev", "test", "unknown"), &logBuffer{}); e == nil {
		t.Fatal("audit aliases database")
	}
	os.Remove(c.Operations.AuditFile)
	if e := os.WriteFile(c.Operations.AuditFile, nil, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := New(c, func(context.Context) error { return nil }, version.New("dev", "test", "unknown"), &logBuffer{}); e == nil {
		t.Fatal("public audit file accepted")
	}
}

type loginAdapter struct{}

func (loginAdapter) AuthorizationURL(state, _, _ string) string {
	return "https://github.com/login/oauth/authorize?state=" + state
}
func (loginAdapter) Exchange(context.Context, string, string, string) (provider.Identity, error) {
	return provider.Identity{Provider: "github", Namespace: "app", Subject: "subject"}, nil
}
func TestAuditFailureDoesNotChangeAuthenticationOrRevocation(t *testing.T) {
	c := configuration(t)
	c.Bindings = []config.Binding{{Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Mail: "owner@example.test"}}
	db, e := store.Open(c.Database)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	logs := &logBuffer{}
	sink := &controlledStorage{fail: true}
	r := newRuntime(c, db.Check, version.New("dev", "test", "unknown"), logs, sink)
	defer r.Close()
	h := gateway.New(c, db, map[string]provider.Adapter{"github": loginAdapter{}}, r).Handler()
	request := func(method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, c.PublicURL+path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		req.Header.Set("Origin", c.PublicURL)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	start := request("POST", "/login/github", nil)
	if start.Code != 200 {
		t.Fatal(start.Code)
	}
	match := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(start.Body.String())
	if len(match) != 2 {
		t.Fatal(start.Body.String())
	}
	u, _ := url.Parse(html.UnescapeString(match[1]))
	callback := request("GET", "/callback/github?state="+u.Query().Get("state")+"&code=SECRET", start.Result().Cookies()[0])
	if callback.Code != 303 {
		t.Fatal(callback.Code, callback.Body.String())
	}
	var session *http.Cookie
	for _, cookie := range callback.Result().Cookies() {
		if cookie.Name == "__Host-porter_session" {
			session = cookie
		}
	}
	if session == nil {
		t.Fatal("session not issued")
	}
	req := httptest.NewRequest("GET", c.PublicURL+"/identity", nil)
	req.AddCookie(session)
	req.Header.Set("Authorization", "Bearer "+c.ProxyKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || w.Header().Get("X-Porter-User-ID") != "u1" {
		t.Fatal("audit failure changed identity")
	}
	if w = request("POST", "/logout", session); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if _, e = db.Session(session.Value); !errors.Is(e, store.ErrMissing) {
		t.Fatal("audit failure changed revocation", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if sink.writes.Load() < 3 || strings.Contains(logs.String(), "SECRET") || strings.Contains(logs.String(), session.Value) {
		t.Fatal("audit failure was not safely observed")
	}
}
func TestMetricsDoNotUseRawRequestLabels(t *testing.T) {
	c := configuration(t)
	r, e := New(c, func(context.Context) error { return nil }, version.New("dev", "test", "unknown"), &logBuffer{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	h := observe.Wrap(http.NotFoundHandler(), r)
	for i := range 20 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("SECRET", "https://porter.test/SECRET-"+strconv.Itoa(i)+"?code=SECRET", nil))
	}
	body := admin(r, c, "/metrics", "127.0.0.1:1000", "").Body.String()
	if strings.Contains(body, "SECRET") || !strings.Contains(body, `path="other"`) || !strings.Contains(body, `method="OTHER"`) {
		t.Fatal("unbounded or sensitive request labels")
	}
}
