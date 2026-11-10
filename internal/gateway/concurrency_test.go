package gateway

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/provider"
	"github.com/soulteary/porter/internal/store"
)

type blockedExchange struct {
	name             string
	entered, release chan struct{}
	calls            atomic.Int32
}

func (p *blockedExchange) AuthorizationURL(state, _, _ string) string {
	return "https://fixture.invalid/?state=" + state
}
func (p *blockedExchange) Exchange(context.Context, string, string, string) (provider.Identity, error) {
	p.calls.Add(1)
	close(p.entered)
	<-p.release
	return provider.Identity{Provider: p.name, Namespace: "app", Subject: "123"}, nil
}
func TestLogoutDuringExchangeSurvivesRestart(t *testing.T) {
	for _, name := range []string{"github", "google", "wechat", "qq"} {
		t.Run(name, func(t *testing.T) {
			g, _ := fixture(t)
			defer g.CloseIdleConnections()
			path := filepath.Join(t.TempDir(), "concurrent.db")
			db, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Close() })
			g.db = db
			g.cfg.Providers = map[string]config.Provider{name: {ClientID: "app", ClientSecret: "SECRET"}}
			g.cfg.Bindings = []config.Binding{{Provider: name, Namespace: "app", Subject: "123", UserID: "internal-1", Mail: "owner@example.test"}}
			p := &blockedExchange{name: name, entered: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			unblock := func() { once.Do(func() { close(p.release) }) }
			defer unblock()
			g.providers = map[string]provider.Adapter{name: p}
			start := request(g, "POST", "/login/"+name, nil, g.cfg.PublicURL, "")
			match := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(start.Body.String())
			if start.Code != 200 || len(match) != 2 || len(start.Result().Cookies()) != 1 {
				t.Fatal("login did not start")
			}
			target, err := url.Parse(html.UnescapeString(match[1]))
			if err != nil {
				t.Fatal(err)
			}
			browser := start.Result().Cookies()[0]
			callback := "/callback/" + name + "?state=" + target.Query().Get("state") + "&code=SECRET"
			completed := make(chan *httptest.ResponseRecorder, 1)
			go func() { completed <- request(g, "GET", callback, browser, "", "") }()
			select {
			case <-p.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("exchange did not start")
			}
			if replay := request(g, "GET", callback, browser, "", ""); replay.Code != 400 || p.calls.Load() != 1 {
				t.Fatal("parallel callback replayed exchange")
			}
			if logout := request(g, "POST", "/logout", browser, g.cfg.PublicURL, ""); logout.Code != 303 {
				t.Fatal("logout failed")
			}
			unblock()
			select {
			case result := <-completed:
				if result.Code != 400 {
					t.Fatal("in-flight callback survived logout", result.Code)
				}
				for _, cookie := range result.Result().Cookies() {
					if cookie.Name == g.cookieName("session") && cookie.Value != "" {
						t.Fatal("revoked exchange issued session")
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("exchange did not complete")
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			g.db = db
			record := store.Record{Expires: time.Now().Add(time.Hour), UserID: "internal-1", Binding: g.cfg.Bindings[0].Revision(), Browser: store.Key(browser.Value)}
			if err = db.RotateSession(strings.Repeat("T", 43), "", record); !errors.Is(err, store.ErrMissing) {
				t.Fatal("restart revived revoked login family", err)
			}
			if response := request(g, "GET", callback, browser, "", ""); response.Code != http.StatusBadRequest || p.calls.Load() != 1 {
				t.Fatal("restart replayed authorization code")
			}
		})
	}
}
