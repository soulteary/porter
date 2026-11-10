package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/store"
)

// Uses local adapters and disposable databases; never sends a code upstream.
func FuzzCallbackSingleUse(f *testing.F) {
	state, browser := strings.Repeat("S", 43), strings.Repeat("B", 43)
	for _, query := range []string{
		"state=" + state + "&code=code",
		"state=" + state + "&code=one&code=two",
		"state=" + state + "&error=access_denied",
		"state=" + state + "&state=" + state + "&code=code",
		"state=%zz&code=code",
		"state=" + state + "&code=" + strings.Repeat("x", 4097),
	} {
		f.Add(query, "__Host-porter_transaction="+browser)
	}
	f.Add("state="+state+"&code=code", "__Host-porter_transaction=wrong-browser")
	f.Fuzz(func(t *testing.T, query, cookie string) {
		if len(query) > 32768 || len(cookie) > 1024 {
			t.Skip()
		}
		g, adapter := fixture(t)
		defer g.CloseIdleConnections()
		expiry := time.Now().Add(5 * time.Minute)
		if err := g.db.Start(state, browser, "", store.Record{Provider: "github", Namespace: "app", Expires: expiry, Verifier: strings.Repeat("v", 43), Nonce: "nonce"}); err != nil {
			t.Fatal(err)
		}
		input := func() *http.Request {
			req := httptest.NewRequest("GET", g.cfg.PublicURL+"/callback/github", nil)
			req.URL.RawQuery = query
			req.Header.Set("Cookie", cookie)
			return req
		}
		bound := g.readCookie(input(), "transaction") == browser
		call := func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			g.Handler().ServeHTTP(w, input())
			return w
		}
		first, second := call(), call()
		if adapter.calls > 1 {
			t.Fatal("callback replayed an authorization exchange")
		}
		parsed, err := url.ParseQuery(query)
		eligible := err == nil && bound && len(parsed["state"]) == 1 && parsed.Get("state") == state && len(parsed["code"]) == 1 && parsed.Get("code") != "" && len(parsed.Get("code")) <= 4096 && len(parsed["error"]) <= 1 && parsed.Get("error") == ""
		if !eligible && adapter.calls != 0 {
			t.Fatal("unbound callback reached provider")
		}
		if first.Code == 303 && (second.Code == 303 || adapter.calls != 1) {
			t.Fatal("successful callback was reusable")
		}
		for _, response := range []*http.Response{first.Result(), second.Result()} {
			for _, value := range response.Cookies() {
				if value.Name == g.cookieName("session") && value.Value != "" {
					if !eligible || !value.Secure || !value.HttpOnly || value.SameSite != http.SameSiteLaxMode || value.Path != "/" || value.Domain != "" {
						t.Fatal("invalid callback issued an unsafe session")
					}
				}
			}
		}
	})
}
