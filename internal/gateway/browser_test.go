package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/provider"
	"github.com/soulteary/porter/internal/store"
)

type browserAdapter struct{ name string }

func (a browserAdapter) AuthorizationURL(state, _, _ string) string {
	host := map[string]string{"github": "https://github.com/login/oauth/authorize", "google": "https://accounts.google.com/o/oauth2/v2/auth", "wechat": "https://open.weixin.qq.com/connect/qrconnect", "qq": "https://graph.qq.com/oauth2.0/authorize"}[a.name]
	return host + "?state=" + state
}
func (a browserAdapter) Exchange(context.Context, string, string, string) (provider.Identity, error) {
	return provider.Identity{Provider: a.name, Namespace: "app-" + a.name, Subject: "subject"}, nil
}

func TestBrowserForms(t *testing.T) {
	chrome := os.Getenv("PORTER_CHROME")
	if chrome == "" {
		t.Skip("set PORTER_CHROME to run isolated Chromium acceptance")
	}
	db, e := store.Open(filepath.Join(t.TempDir(), "browser.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s := httptest.NewUnstartedServer(nil)
	defer s.Close()
	origin := "https://" + s.Listener.Addr().String()
	c := config.Config{PublicURL: origin, LandingURL: origin + "/app", SessionSeconds: 3600, Providers: map[string]config.Provider{}, Bindings: []config.Binding{}}
	adapters := map[string]provider.Adapter{}
	for _, name := range []string{"github", "google", "wechat", "qq"} {
		c.Providers[name] = config.Provider{ClientID: "app-" + name}
		c.Bindings = append(c.Bindings, config.Binding{Provider: name, Namespace: "app-" + name, Subject: "subject", UserID: "internal-1", Mail: "owner@example.test"})
		adapters[name] = browserAdapter{name: name}
	}
	g := New(c, db, adapters)
	h := g.Handler()
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app" {
			h.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("Referer") != "" {
			t.Error("callback leaked referrer to landing page")
		}
		session, e := db.Session(g.readCookie(r, "session"))
		if e != nil {
			w.WriteHeader(401)
			fmt.Fprint(w, "Login required")
			return
		}
		fmt.Fprintf(w, "Signed in: %s", session.Provider)
	})
	s.StartTLS()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../tests/browser.mjs", origin, chrome)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("browser acceptance: %v\n%s", e, out)
	} else {
		t.Log(string(out))
	}
}
