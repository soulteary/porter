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

// All callbacks start together. Exactly one may consume the transaction, exchange
// the code and issue a session; the winner must remain usable after reopening.
func TestConcurrentCallbacksHaveSinglePersistentWinner(t *testing.T) {
	for _, name := range []string{"github", "google", "wechat", "qq"} {
		t.Run(name, func(t *testing.T) {
			g, _ := fixture(t)
			defer g.CloseIdleConnections()
			path := filepath.Join(t.TempDir(), "winner.db")
			db, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if db != nil {
					db.Close()
				}
			})
			g.db = db
			g.cfg.Providers = map[string]config.Provider{name: {ClientID: "app", ClientSecret: "SECRET"}}
			g.cfg.Bindings[0].Provider = name
			p := &blockedExchange{name: name, entered: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			unblock := func() { once.Do(func() { close(p.release) }) }
			defer unblock()
			g.providers = map[string]provider.Adapter{name: p}
			state, browser := strings.Repeat("S", 43), strings.Repeat("B", 43)
			if err := db.Start(state, browser, "", store.Record{Provider: name, Namespace: "app", Expires: time.Now().Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			cookie := &http.Cookie{Name: g.cookieName("transaction"), Value: browser}
			const count = 16
			barrier := make(chan struct{})
			responses := make(chan *httptest.ResponseRecorder, count)
			var ready sync.WaitGroup
			ready.Add(count)
			for i := 0; i < count; i++ {
				go func() {
					ready.Done()
					<-barrier
					responses <- request(g, "GET", "/callback/"+name+"?state="+state+"&code=SECRET", cookie, "", "")
				}()
			}
			ready.Wait()
			close(barrier)
			select {
			case <-p.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("no exchange winner")
			}
			for i := 0; i < count-1; i++ {
				select {
				case response := <-responses:
					if response.Code != http.StatusBadRequest {
						t.Fatal("losing callback was not rejected", response.Code)
					}
					for _, c := range response.Result().Cookies() {
						if c.Name == g.cookieName("session") && c.Value != "" {
							t.Fatal("loser issued a session")
						}
					}
				case <-time.After(5 * time.Second):
					t.Fatal("losing callback did not finish")
				}
			}
			unblock()
			var winner *httptest.ResponseRecorder
			select {
			case winner = <-responses:
			case <-time.After(5 * time.Second):
				t.Fatal("winner did not finish")
			}
			if winner.Code != http.StatusSeeOther || p.calls.Load() != 1 {
				t.Fatal("not exactly one successful exchange", winner.Code, p.calls.Load())
			}
			var session *http.Cookie
			for _, c := range winner.Result().Cookies() {
				if c.Name == g.cookieName("session") && c.Value != "" {
					if session != nil {
						t.Fatal("multiple session cookies")
					}
					session = c
				}
			}
			if session == nil {
				t.Fatal("winner did not issue a session")
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			g.db = db
			if result := request(g, "GET", "/identity", session, "", "Bearer "+g.cfg.ProxyKey); result.Code != http.StatusOK {
				t.Fatal("winning session was not durable", result.Code)
			}
			if replay := request(g, "GET", "/callback/"+name+"?state="+state+"&code=SECRET", cookie, "", ""); replay.Code != 400 || p.calls.Load() != 1 {
				t.Fatal("restart replayed exchange")
			}
		})
	}
}
