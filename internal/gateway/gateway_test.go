package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, r)
	return w
}
func begin(t *testing.T, g *Gateway) (string, *http.Cookie) {
	t.Helper()
	w := request(g, "POST", "/login/github", nil, g.cfg.PublicURL, "")
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	u, _ := url.Parse(w.Header().Get("Location"))
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
	w = request(g, "GET", "/auth", sess, "", "Bearer "+g.cfg.ProxyKey)
	if w.Code != 200 || w.Header().Get("X-User-Mail") != "owner@example.test" || w.Header().Get("X-Porter-User-ID") != "internal-1" {
		t.Fatal(w.Code, w.Header())
	}
	if f.calls != 1 {
		t.Fatal(f.calls)
	}
	if w = request(g, "GET", "/callback/github?state="+state+"&code=code", browser, "", ""); w.Code != 400 || f.calls != 1 {
		t.Fatal("callback replay accepted")
	}
	if w = request(g, "GET", "/auth", sess, "", ""); w.Code != 401 {
		t.Fatal("proxy authentication bypass")
	}
	if w = request(g, "POST", "/logout", sess, g.cfg.PublicURL, ""); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w = request(g, "GET", "/auth", sess, "", "Bearer "+g.cfg.ProxyKey); w.Code != 401 {
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
	e := g.db.Put("sessions", token, store.Record{Expires: time.Now().Add(time.Hour), Provider: "github", Namespace: "app", Subject: "123"})
	if e != nil {
		t.Fatal(e)
	}
	if w := request(g, "GET", "/auth", &http.Cookie{Name: g.cookieName("session"), Value: token}, "", "Bearer "+g.cfg.ProxyKey); w.Code != 403 {
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
	if w := request(g, "GET", "/auth", &http.Cookie{Name: g.cookieName("session"), Value: strings.Repeat("a", 43)}, "", "Bearer "+g.cfg.ProxyKey); w.Code != 503 {
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
			if e := g.db.Put("sessions", token, store.Record{Expires: time.Now().Add(time.Hour), Provider: "github", Namespace: "app", Subject: "123"}); e != nil {
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
