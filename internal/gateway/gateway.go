// Package gateway owns external login sessions and exports identity to a trusted proxy.
package gateway

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/provider"
	"github.com/soulteary/porter/internal/store"
)

type Gateway struct {
	cfg       config.Config
	db        *store.Store
	providers map[string]provider.Adapter
	origin    *url.URL
	mu        sync.Mutex
	limits    map[string]window
}
type window struct {
	count int
	until time.Time
}

func New(c config.Config, s *store.Store, p map[string]provider.Adapter) *Gateway {
	u, _ := url.Parse(c.PublicURL)
	return &Gateway{cfg: c, db: s, providers: p, origin: u, limits: map[string]window{}}
}
func (g *Gateway) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	m.HandleFunc("GET /login", g.login)
	m.HandleFunc("POST /login/{provider}", g.start)
	m.HandleFunc("GET /callback/{provider}", g.callback)
	m.HandleFunc("POST /logout", g.logout)
	m.HandleFunc("GET /auth", g.auth)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.URL.Path != "/auth" && r.URL.Path != "/healthz" && !strings.EqualFold(r.Host, g.origin.Host) {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		m.ServeHTTP(w, r)
	})
}

var page = template.Must(template.New("login").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Porter</title><h1>Sign in</h1>{{range .}}<form method="post" action="/login/{{.}}"><button type="submit">Continue with {{.}}</button></form>{{end}}<form method="post" action="/logout"><button type="submit">Sign out</button></form></html>`))

func (g *Gateway) login(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(g.providers))
	for k := range g.providers {
		names = append(names, k)
	}
	sort.Strings(names)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, names)
}
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (g *Gateway) cookieName(kind string) string {
	if g.cfg.Development {
		return "porter_" + kind
	}
	return "__Host-porter_" + kind
}
func (g *Gateway) cookie(w http.ResponseWriter, kind, value string, expires time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: g.cookieName(kind), Value: value, Path: "/", Expires: expires, MaxAge: maxAge, HttpOnly: true, Secure: !g.cfg.Development, SameSite: http.SameSiteLaxMode})
}
func (g *Gateway) readCookie(r *http.Request, kind string) string {
	var result string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == g.cookieName(kind) {
			count++
			result = c.Value
		}
	}
	if count != 1 || len(result) != 43 {
		return ""
	}
	return result
}
func (g *Gateway) sameOrigin(r *http.Request) bool { return r.Header.Get("Origin") == g.cfg.PublicURL }
func (g *Gateway) permit(r *http.Request) bool {
	// Use the direct peer, never untrusted X-Forwarded-For. At a reverse proxy this
	// is deliberately a conservative shared limit; configure edge limits as well.
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		host = r.RemoteAddr
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for k, v := range g.limits {
		if !now.Before(v.until) {
			delete(g.limits, k)
		}
	}
	v, ok := g.limits[host]
	if !ok {
		if len(g.limits) >= 4096 {
			return false
		}
		v = window{until: now.Add(time.Minute)}
	}
	if v.count >= 30 {
		return false
	}
	v.count++
	g.limits[host] = v
	return true
}
func (g *Gateway) start(w http.ResponseWriter, r *http.Request) {
	p, ok := g.providers[r.PathValue("provider")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !g.sameOrigin(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if !g.permit(r) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "login rate limited", http.StatusTooManyRequests)
		return
	}
	state, e := randomToken()
	if e != nil {
		unavailable(w)
		return
	}
	browser, e := randomToken()
	if e != nil {
		unavailable(w)
		return
	}
	verifier, e := randomToken()
	if e != nil {
		unavailable(w)
		return
	}
	nonce, e := randomToken()
	if e != nil {
		unavailable(w)
		return
	}
	expiry := time.Now().Add(5 * time.Minute)
	if e = g.db.Put("transactions", state, store.Record{Expires: expiry, Provider: r.PathValue("provider"), Browser: store.Key(browser), Verifier: verifier, Nonce: nonce}); e != nil {
		unavailable(w)
		return
	}
	g.cookie(w, "transaction", browser, expiry, 300)
	http.Redirect(w, r, p.AuthorizationURL(state, verifier, nonce), http.StatusSeeOther)
}
func (g *Gateway) callback(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	p, ok := g.providers[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || len(q["state"]) != 1 || len(q.Get("state")) != 43 || len(q["code"]) > 1 || len(q["error"]) > 1 {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	browser := g.readCookie(r, "transaction")
	if browser == "" {
		http.Error(w, "invalid login transaction", http.StatusBadRequest)
		return
	}
	tx, e := g.db.Consume(q.Get("state"), browser, name)
	if e != nil {
		if errors.Is(e, store.ErrMissing) {
			http.Error(w, "invalid login transaction", http.StatusBadRequest)
		} else {
			unavailable(w)
		}
		return
	}
	g.cookie(w, "transaction", "", time.Unix(1, 0), -1)
	if q.Get("error") != "" || q.Get("code") == "" || len(q.Get("code")) > 4096 {
		http.Error(w, "authorization was not completed", http.StatusBadRequest)
		return
	}
	id, e := p.Exchange(r.Context(), q.Get("code"), tx.Verifier, tx.Nonce)
	if e != nil {
		http.Error(w, "provider authentication failed", http.StatusBadGateway)
		return
	}
	if id.Provider != name || id.Namespace != g.cfg.Providers[name].ClientID {
		http.Error(w, "invalid provider identity", http.StatusBadGateway)
		return
	}
	if _, ok = g.cfg.Resolve(id.Provider, id.Namespace, id.Subject); !ok {
		http.Error(w, "identity is not linked; contact the administrator", http.StatusForbidden)
		return
	}
	token, e := randomToken()
	if e != nil {
		unavailable(w)
		return
	}
	expiry := time.Now().Add(time.Duration(g.cfg.SessionSeconds) * time.Second)
	if e = g.db.Put("sessions", token, store.Record{Expires: expiry, Provider: id.Provider, Namespace: id.Namespace, Subject: id.Subject}); e != nil {
		unavailable(w)
		return
	}
	if old := g.readCookie(r, "session"); old != "" {
		if e = g.db.Delete("sessions", old); e != nil {
			_ = g.db.Delete("sessions", token)
			unavailable(w)
			return
		}
	}
	g.cookie(w, "session", token, expiry, g.cfg.SessionSeconds)
	http.Redirect(w, r, g.cfg.LandingURL, http.StatusSeeOther)
}
func (g *Gateway) auth(w http.ResponseWriter, r *http.Request) {
	// This endpoint is for a proxy subrequest, not for browser navigation.
	provided := r.Header.Get("Authorization")
	if subtle.ConstantTimeCompare([]byte(provided), []byte("Bearer "+g.cfg.ProxyKey)) != 1 {
		http.Error(w, "unauthorized proxy", http.StatusUnauthorized)
		return
	}
	token := g.readCookie(r, "session")
	if token == "" {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	s, e := g.db.Get("sessions", token)
	if e != nil {
		if errors.Is(e, store.ErrMissing) {
			http.Error(w, "login required", http.StatusUnauthorized)
		} else {
			unavailable(w)
		}
		return
	}
	b, ok := g.cfg.Resolve(s.Provider, s.Namespace, s.Subject)
	if !ok {
		http.Error(w, "identity is not linked", http.StatusForbidden)
		return
	}
	if g.cfg.StargateURL != "" {
		g.authorize(w, r, b)
		return
	}
	// These are claims for the next trusted hop, not a Warden authorization decision.
	w.Header().Set("X-Porter-User-ID", b.UserID)
	if b.Mail != "" {
		w.Header().Set("X-User-Mail", b.Mail)
	}
	if b.Phone != "" {
		w.Header().Set("X-User-Phone", b.Phone)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"user_id": b.UserID, "provider": s.Provider})
}
func (g *Gateway) logout(w http.ResponseWriter, r *http.Request) {
	if !g.sameOrigin(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if token := g.readCookie(r, "session"); token != "" {
		if e := g.db.Delete("sessions", token); e != nil {
			unavailable(w)
			return
		}
	}
	g.cookie(w, "session", "", time.Unix(1, 0), -1)
	http.Redirect(w, r, g.cfg.PublicURL+"/login", http.StatusSeeOther)
}
func unavailable(w http.ResponseWriter) {
	http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
}

// authorize delegates the access decision over a fixed server-to-server endpoint.
// No browser cookie, password or client identity header enters this request.
func (g *Gateway) authorize(w http.ResponseWriter, r *http.Request, b config.Binding) {
	req, e := http.NewRequestWithContext(r.Context(), http.MethodGet, g.cfg.StargateURL, nil)
	if e != nil {
		unavailable(w)
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Stargate-Header-Auth", g.cfg.StargateSecret)
	if b.Mail != "" {
		req.Header.Set("X-User-Mail", b.Mail)
	} else {
		req.Header.Set("X-User-Phone", b.Phone)
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// Default Stargate output headers only; never forward Set-Cookie or secrets.
		for _, key := range []string{"X-Forwarded-User", "X-Auth-User", "X-Auth-Email", "X-Auth-Phone", "X-Auth-Name", "X-Auth-Role", "X-Auth-Scopes"} {
			if value := resp.Header.Get(key); value != "" {
				w.Header().Set(key, value)
			}
		}
		w.WriteHeader(http.StatusOK)
	case http.StatusUnauthorized, http.StatusForbidden:
		http.Error(w, "access denied", resp.StatusCode)
	default:
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
	}
}
