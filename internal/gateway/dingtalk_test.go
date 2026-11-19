package gateway

import (
	"context"
	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/provider"
	"github.com/soulteary/porter/internal/store"
	"net/http"
	"strings"
	"testing"
	"time"
)

type dingFake struct{ calls int }

func (a *dingFake) AuthorizationURL(string, string, string) string {
	return "https://login.dingtalk.com/"
}
func (a *dingFake) Exchange(context.Context, string, string, string) (provider.Identity, error) {
	a.calls++
	return provider.Identity{Provider: "dingtalk", Namespace: "app", Subject: "123"}, nil
}
func TestDingTalkCallbackIsolation(t *testing.T) {
	for _, query := range []string{"authCode=CODE", "code=CODE", "authCode=CODE&code=CODE", "authCode=A&authCode=B", "error=access_denied", "authCode=", "authCode=%20CODE", "authCode=CODE%0A", "authCode=CODE&code=", "authCode=CODE&authCode="} {
		t.Run(query, func(t *testing.T) {
			g, _ := fixture(t)
			defer g.CloseIdleConnections()
			a := &dingFake{}
			g.providers = map[string]provider.Adapter{"dingtalk": a}
			g.cfg.Providers = map[string]config.Provider{"dingtalk": {ClientID: "app", ClientSecret: "SECRET"}}
			g.cfg.Bindings[0].Provider = "dingtalk"
			state, browser := strings.Repeat("S", 43), strings.Repeat("B", 43)
			if err := g.db.Start(state, browser, "", store.Record{Provider: "dingtalk", Namespace: "app", Expires: time.Now().Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			cookie := &http.Cookie{Name: g.cookieName("transaction"), Value: browser}
			path := "/callback/dingtalk?state=" + state + "&" + query
			result := request(g, "GET", path, cookie, "", "")
			expected := 400
			if query == "authCode=CODE" {
				expected = 303
			}
			if result.Code != expected {
				t.Fatal(result.Code)
			}
			request(g, "GET", path, cookie, "", "")
			if query == "authCode=CODE" {
				if a.calls != 1 {
					t.Fatal("code replayed")
				}
			} else if a.calls != 0 {
				t.Fatal("invalid callback exchanged code")
			}
		})
	}
}
