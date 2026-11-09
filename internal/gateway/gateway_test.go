package gateway

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/provider"
	"github.com/soulteary/porter/internal/store"
)

type fake struct{ calls int }

func (f *fake) AuthorizationURL(state, verifier, nonce string) string {
	return "https://upstream.test/?state=" + state
}
func (f *fake) Exchange(context.Context, string, string, string) (provider.Identity, error) {
	f.calls++
	return provider.Identity{Provider: "github", Namespace: "app", Subject: "123"}, nil
}
func fixture(t *testing.T) (*Gateway, *fake) {
	t.Helper()
	s, e := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	f := &fake{}
	c := config.Config{PublicURL: "https://porter.test", LandingURL: "https://porter.test/app", SessionSeconds: 3600, ProxyKey: strings.Repeat("k", 32), Providers: map[string]config.Provider{"github": {ClientID: "app", ClientSecret: "secret"}}, Bindings: []config.Binding{{Provider: "github", Namespace: "app", Subject: "123", UserID: "internal-1", Mail: "owner@example.test"}}}
	return New(c, s, map[string]provider.Adapter{"github": f}), f
}
func request(g *Gateway, method, path string, cookie *http.Cookie, origin, authorization string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://porter.test"+path, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	r.Header.Set("X-User-Mail", "attacker@example.test")
	r.Header.Set("X-Forwarded-Uri", "/app?tab=one")
	r.Header.Set("X-Forwarded-Method", "GET")
	r.Header.Set("X-Forwarded-Host", "porter.test")
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, r)
	return w
}
func begin(t *testing.T, g *Gateway) (string, *http.Cookie) {
	t.Helper()
	w := request(g, "POST", "/login/github", nil, g.cfg.PublicURL, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	match := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("missing navigation link")
	}
	u, _ := url.Parse(html.UnescapeString(match[1]))
	return u.Query().Get("state"), w.Result().Cookies()[0]
}
func TestLoginLifecycle(t *testing.T) {
	g, f := fixture(t)
	state, browser := begin(t, g)
	w := request(g, "GET", "/callback/github?state="+state+"&code=code", browser, "", "")
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	var sess *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == g.cookieName("session") {
			sess = c
		}
	}
	if sess == nil || !sess.Secure || !sess.HttpOnly || sess.Domain != "" || sess.SameSite != http.SameSiteLaxMode {
		t.Fatal("insecure session cookie")
	}
	w = request(g, "GET", "/identity", sess, "", "Bearer "+g.cfg.ProxyKey)
	if w.Code != 200 || w.Header().Get("X-User-Mail") != "owner@example.test" || w.Header().Get("X-Porter-User-ID") != "internal-1" {
		t.Fatal(w.Code, w.Header())
	}
	if f.calls != 1 {
		t.Fatal(f.calls)
	}
	if w = request(g, "GET", "/callback/github?state="+state+"&code=code", browser, "", ""); w.Code != 400 || f.calls != 1 {
		t.Fatal("callback replay accepted")
	}
	if w = request(g, "GET", "/identity", sess, "", ""); w.Code != 401 {
		t.Fatal("proxy authentication bypass")
	}
	if w = request(g, "POST", "/logout", sess, g.cfg.PublicURL, ""); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w = request(g, "GET", "/identity", sess, "", "Bearer "+g.cfg.ProxyKey); w.Code != 401 {
		t.Fatal("logout did not revoke")
	}
}
func TestTransactionBinding(t *testing.T) {
	g, f := fixture(t)
	state, browser := begin(t, g)
	bad := *browser
	bad.Value = strings.Repeat("a", 43)
	if w := request(g, "GET", "/callback/github?state="+state+"&code=x", &bad, "", ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if f.calls != 0 {
		t.Fatal("exchange before binding check")
	}
	if w := request(g, "GET", "/callback/github?state="+state+"&code=x", browser, "", ""); w.Code != 303 {
		t.Fatal("invalid browser consumed valid transaction")
	}
	if w := request(g, "POST", "/login/github", nil, "https://evil.test", ""); w.Code != 403 {
		t.Fatal("cross-site login accepted")
	}
	if w := request(g, "POST", "/logout", nil, "https://evil.test", ""); w.Code != 403 {
		t.Fatal("cross-site logout accepted")
	}
}
func TestUnlinkedAndRemovedBinding(t *testing.T) {
	g, _ := fixture(t)
	state, browser := begin(t, g)
	g.cfg.Bindings = nil
	if w := request(g, "GET", "/callback/github?state="+state+"&code=x", browser, "", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	token := strings.Repeat("a", 43)
	e := seedSession(g, token, store.Record{Expires: time.Now().Add(time.Hour), Provider: "github", Namespace: "app", Subject: "123"})
	if e != nil {
		t.Fatal(e)
	}
	if w := request(g, "GET", "/identity", &http.Cookie{Name: g.cookieName("session"), Value: token}, "", "Bearer "+g.cfg.ProxyKey); w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestCallbackDenialAndDuplicateState(t *testing.T) {
	g, f := fixture(t)
	state, browser := begin(t, g)
	if w := request(g, "GET", "/callback/github?state="+state+"&state="+state+"&code=x", browser, "", ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := request(g, "GET", "/callback/github?state="+state+"&error=access_denied", browser, "", ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if f.calls != 0 {
		t.Fatal(f.calls)
	}
	if w := request(g, "GET", "/callback/github?state="+state+"&code=x", browser, "", ""); w.Code != 400 {
		t.Fatal("denied transaction reusable")
	}
}
func TestStorageFailureFailsClosed(t *testing.T) {
	g, _ := fixture(t)
	g.db.Close()
	if w := request(g, "GET", "/identity", &http.Cookie{Name: g.cookieName("session"), Value: strings.Repeat("a", 43)}, "", "Bearer "+g.cfg.ProxyKey); w.Code != 503 {
		t.Fatal(w.Code)
	}
}

func TestStargateDelegation(t *testing.T) {
	for _, status := range []int{200, 401, 403, 302, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			g, _ := fixture(t)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/_auth" || r.Header.Get("X-User-Mail") != "owner@example.test" || r.Header.Get("X-Stargate-Header-Auth") != strings.Repeat("s", 32) {
					t.Error("missing canonical identity or credential")
				}
				if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Stargate-Password") != "" {
					t.Error("client credentials leaked")
				}
				w.Header().Set("X-Forwarded-User", "internal-1")
				w.Header().Set("X-Auth-User", "internal-1")
				w.Header().Set("X-Auth-Role", "reader")
				w.Header().Set("Set-Cookie", "unsafe=1")
				w.Header().Set("X-Stargate-Header-Auth", "secret")
				w.Header().Set("Location", "https://evil.test")
				w.WriteHeader(status)
			}))
			defer upstream.Close()
			g.cfg.StargateURL = upstream.URL + "/_auth"
			g.cfg.StargateSecret = strings.Repeat("s", 32)
			token := strings.Repeat("z", 43)
			if e := seedSession(g, token, store.Record{Expires: time.Now().Add(time.Hour), Provider: "github", Namespace: "app", Subject: "123"}); e != nil {
				t.Fatal(e)
			}
			w := request(g, "GET", "/auth", &http.Cookie{Name: g.cookieName("session"), Value: token}, "", "Bearer "+g.cfg.ProxyKey)
			want := status
			if status != 200 && status != 401 && status != 403 {
				want = 503
			}
			if w.Code != want {
				t.Fatalf("want %d got %d", want, w.Code)
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-Stargate-Header-Auth") != "" || w.Header().Get("Location") != "" {
				t.Fatal("upstream headers leaked")
			}
			if status == 200 && w.Header().Get("X-Auth-Role") != "reader" {
				t.Fatal("missing authorized role")
			}
			if status != 200 && w.Header().Get("X-Forwarded-User") != "" {
				t.Fatal("identity on failed authorization")
			}
		})
	}
}

func seedSession(g *Gateway, token string, r store.Record) error {
	browser := "browser-" + token
	state := "state-" + token
	if e := g.db.Start(state, browser, "", store.Record{Expires: r.Expires, Provider: r.Provider}); e != nil {
		return e
	}
	binding, ok := g.cfg.Resolve(r.Provider, r.Namespace, r.Subject)
	r.Browser = store.Key(browser)
	r.UserID = "internal-1"
	r.Binding = "removed"
	if ok {
		r.UserID = binding.UserID
		r.Binding = binding.Revision()
	}
	return g.db.RotateSession(token, "", r)
}

func TestAuthorizationRequiresStargate(t *testing.T) {
	g, _ := fixture(t)
	token := strings.Repeat("a", 43)
	if e := seedSession(g, token, store.Record{Expires: time.Now().Add(time.Hour), Provider: "github", Namespace: "app", Subject: "123"}); e != nil {
		t.Fatal(e)
	}
	cookie := &http.Cookie{Name: g.cookieName("session"), Value: token}
	if w := request(g, "GET", "/auth", cookie, "", "Bearer "+g.cfg.ProxyKey); w.Code != 503 || w.Header().Get("X-Porter-User-ID") != "" {
		t.Fatal("identity-only configuration granted access")
	}
	if w := request(g, "GET", "/identity", cookie, "", "Bearer "+g.cfg.ProxyKey); w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestBindingReassignmentInvalidatesSession(t *testing.T) {
	g, _ := fixture(t)
	token := strings.Repeat("a", 43)
	if e := seedSession(g, token, store.Record{Expires: time.Now().Add(time.Hour), Provider: "github", Namespace: "app", Subject: "123"}); e != nil {
		t.Fatal(e)
	}
	g.cfg.Bindings[0].UserID = "other-account"
	if w := request(g, "GET", "/identity", &http.Cookie{Name: g.cookieName("session"), Value: token}, "", "Bearer "+g.cfg.ProxyKey); w.Code != 403 {
		t.Fatal("session changed internal account")
	}
}
func TestLogoutDuringExchange(t *testing.T) {
	g, _ := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	g.providers["github"] = &blockedAdapter{entered: entered, release: release}
	state, browser := begin(t, g)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request(g, "GET", "/callback/github?state="+state+"&code=x", browser, "", "") }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("callback never entered exchange")
	}
	if w := request(g, "POST", "/logout", browser, g.cfg.PublicURL, ""); w.Code != 303 {
		t.Fatal(w.Code)
	}
	close(release)
	w := <-done
	if w.Code != 400 {
		t.Fatal("logout did not cancel in-flight login", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == g.cookieName("session") && c.Value != "" {
			t.Fatal("revoked callback issued session")
		}
	}
}

type blockedAdapter struct{ entered, release chan struct{} }

func (a *blockedAdapter) AuthorizationURL(state, verifier, nonce string) string {
	return "https://upstream.test/?state=" + state
}
func (a *blockedAdapter) Exchange(context.Context, string, string, string) (provider.Identity, error) {
	close(a.entered)
	<-a.release
	return provider.Identity{Provider: "github", Namespace: "app", Subject: "123"}, nil
}
func TestStargateIdentityAndContext(t *testing.T) {
	for _, tc := range []struct {
		name, user, primary               string
		duplicate, missingContext, revoke bool
		want                              int
	}{
		{name: "matching", user: "internal-1", primary: "internal-1", want: 200},
		{name: "contact reassigned", user: "other-account", primary: "other-account", want: 403},
		{name: "missing user", primary: "internal-1", want: 403},
		{name: "wrong primary", user: "internal-1", primary: "authenticated", want: 403},
		{name: "duplicate user", user: "internal-1", primary: "internal-1", duplicate: true, want: 403},
		{name: "missing context", user: "internal-1", primary: "internal-1", missingContext: true, want: 503},
		{name: "revoked while authorizing", user: "internal-1", primary: "internal-1", revoke: true, want: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := fixture(t)
			token := strings.Repeat("z", 43)
			if e := seedSession(g, token, store.Record{Expires: time.Now().Add(time.Hour), Provider: "github", Namespace: "app", Subject: "123"}); e != nil {
				t.Fatal(e)
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Forwarded-Uri") != "/app?tab=one" || r.Header.Get("X-Forwarded-Method") != "GET" || r.Header.Get("X-Forwarded-Host") != "porter.test" || r.Header.Get("X-Forwarded-Proto") != "https" {
					t.Error("lost original request context")
				}
				if tc.revoke {
					if e := g.db.Revoke(token, ""); e != nil {
						t.Error(e)
					}
				}
				if tc.user != "" {
					w.Header().Set("X-Auth-User", tc.user)
				}
				if tc.duplicate {
					w.Header().Add("X-Auth-User", tc.user)
				}
				if tc.primary != "" {
					w.Header().Set("X-Forwarded-User", tc.primary)
				}
				w.Header().Set("X-Auth-Role", "admin")
			}))
			defer upstream.Close()
			g.cfg.StargateURL = upstream.URL + "/_auth"
			g.cfg.StargateSecret = strings.Repeat("s", 32)
			r := httptest.NewRequest("GET", "https://porter.test/auth", nil)
			r.Header.Set("Authorization", "Bearer "+g.cfg.ProxyKey)
			r.AddCookie(&http.Cookie{Name: g.cookieName("session"), Value: token})
			if !tc.missingContext {
				r.Header.Set("X-Forwarded-Uri", "/app?tab=one")
				r.Header.Set("X-Forwarded-Method", "GET")
				r.Header.Set("X-Forwarded-Host", "porter.test")
				r.Header.Set("X-Forwarded-Proto", "https")
			}
			w := httptest.NewRecorder()
			g.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("want %d got %d", tc.want, w.Code)
			}
			if tc.want != 200 && (w.Header().Get("X-Auth-User") != "" || w.Header().Get("X-Auth-Role") != "") {
				t.Fatal("identity on failed authorization")
			}
		})
	}
}

func TestCallbackRejectsChangedClientNamespace(t *testing.T) {
	g, f := fixture(t)
	state, browser := begin(t, g)
	g.cfg.Providers["github"] = config.Provider{ClientID: "replacement", ClientSecret: "secret"}
	if w := request(g, "GET", "/callback/github?state="+state+"&code=x", browser, "", ""); w.Code != 400 || f.calls != 0 {
		t.Fatal("exchanged a code after client namespace changed", w.Code, f.calls)
	}
}
