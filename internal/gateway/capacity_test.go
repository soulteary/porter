package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/provider"
	"github.com/soulteary/porter/internal/store"
	bolt "go.etcd.io/bbolt"
)

func TestCapacityReturnsUnavailableWithoutIssuingSession(t *testing.T) {
	for _, bucket := range []string{"transactions", "families", "sessions"} {
		t.Run(bucket, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "porter.db")
			s, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
			raw, err := bolt.Open(path, 0600, nil)
			if err != nil {
				t.Fatal(err)
			}
			expired := time.Now().Add(-time.Hour)
			data, _ := json.Marshal(store.Record{Expires: expired})
			err = raw.Update(func(tx *bolt.Tx) error {
				for i := 0; i < 10000; i++ {
					if err := tx.Bucket([]byte(bucket)).Put([]byte(store.Key(fmt.Sprint(i))), data); err != nil {
						return err
					}
				}
				return nil
			})
			raw.Close()
			if err != nil {
				t.Fatal(err)
			}
			s, err = store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c := config.Config{PublicURL: "https://porter.test", LandingURL: "https://porter.test/app", Database: path, SessionSeconds: 3600, ProxyKey: strings.Repeat("k", 32), Providers: map[string]config.Provider{"github": {ClientID: "app", ClientSecret: "secret"}}, Bindings: []config.Binding{{Provider: "github", Namespace: "app", Subject: "123", UserID: "internal-1", Mail: "owner@example.test"}}}
			f := &fake{}
			g := New(c, s, map[string]provider.Adapter{"github": f}, discardObserver{})
			defer g.CloseIdleConnections()
			if bucket == "sessions" {
				state, browser := begin(t, g)
				w := request(g, "GET", "/callback/github?state="+state+"&code=SECRET", browser, "", "")
				if w.Code != 503 || f.calls != 1 {
					t.Fatal("full sessions did not fail closed", w.Code, f.calls)
				}
				for _, cookie := range w.Result().Cookies() {
					if cookie.Name == g.cookieName("session") && cookie.Value != "" {
						t.Fatal("session issued at capacity")
					}
				}
				if replay := request(g, "GET", "/callback/github?state="+state+"&code=SECRET", browser, "", ""); replay.Code != 400 || f.calls != 1 {
					t.Fatal("failed callback replayed exchange", replay.Code, f.calls)
				}
			} else {
				w := request(g, "POST", "/login/github", nil, c.PublicURL, "")
				if w.Code != 503 || f.calls != 0 {
					t.Fatal("full login storage did not fail closed", w.Code, f.calls)
				}
			}
			if err = s.Prune(time.Now()); err != nil {
				t.Fatal(err)
			}
			state, browser := begin(t, g)
			result := request(g, "GET", "/callback/github?state="+state+"&code=code", browser, "", "")
			if result.Code != 303 {
				t.Fatal("cleanup did not restore login", result.Code)
			}
			var session *http.Cookie
			for _, cookie := range result.Result().Cookies() {
				if cookie.Name == g.cookieName("session") {
					session = cookie
				}
			}
			if session == nil {
				t.Fatal("fresh login did not issue session")
			}
			if w := request(g, "GET", "/identity", session, "", "Bearer "+c.ProxyKey); w.Code != 200 {
				t.Fatal(w.Code)
			}
			if w := request(g, "POST", "/logout", session, c.PublicURL, ""); w.Code != 303 {
				t.Fatal(w.Code)
			}
			if w := request(g, "GET", "/identity", session, "", "Bearer "+c.ProxyKey); w.Code != 401 {
				t.Fatal("logout failed after capacity recovery", w.Code)
			}
		})
	}
}
