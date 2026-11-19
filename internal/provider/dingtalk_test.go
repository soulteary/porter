package provider

import (
	"context"
	"encoding/json"
	"github.com/soulteary/porter/internal/outbound"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDingTalkProtocol(t *testing.T) {
	for _, body := range []string{`{"openId":"opaque","unionId":"different","userId":"directory"}`, `{"unionId":"different","userId":"directory"}`, `{"openId":" bad "}`, `{"openId":"opaque"} {}`} {
		t.Run(body, func(t *testing.T) {
			var hits atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					hits.Add(1)
					var p map[string]string
					if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&p) != nil || p["clientId"] != "app" || p["clientSecret"] != "SECRET" || p["code"] != "CODE" || p["grantType"] != "authorization_code" {
						t.Error("invalid token request")
					}
					w.Write([]byte(`{"accessToken":"TOKEN","refreshToken":"IGNORED"}`))
					return
				}
				if r.Header.Get("x-acs-dingtalk-access-token") != "TOKEN" || r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
					t.Error("invalid identity request")
				}
				w.Write([]byte(body))
			}))
			defer s.Close()
			c := outbound.New(time.Second)
			defer c.CloseIdleConnections()
			a := newDingTalk("app", "SECRET", "https://porter.test/callback/dingtalk", c)
			defer a.CloseIdleConnections()
			a.tokenURL = s.URL + "/token"
			a.userURL = s.URL + "/me"
			u, _ := url.Parse(a.AuthorizationURL("state", "verifier", "nonce"))
			if u.Host != "login.dingtalk.com" || u.Query().Get("scope") != "openid" || u.Query().Get("state") != "state" {
				t.Fatal("invalid authorization URL")
			}
			id, err := a.Exchange(context.Background(), "CODE", "", "")
			if hits.Load() != 1 {
				t.Fatal("exchange repeated")
			}
			if strings.Contains(body, `"openId":"opaque","unionId"`) {
				if err != nil || id.Subject != "opaque" || id.Namespace != "app" || id.Provider != "dingtalk" {
					t.Fatal("invalid identity", err)
				}
			} else if err == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
}
func TestDingTalkSingleAttempt(t *testing.T) {
	for _, mode := range []string{"401", "429", "503", "disconnect", "redirect", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			var hits, redirected atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
			defer target.Close()
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				switch mode {
				case "disconnect":
					c, _, _ := w.(http.Hijacker).Hijack()
					c.Close()
				case "redirect":
					http.Redirect(w, r, target.URL, 307)
				case "timeout":
					select {
					case <-r.Context().Done():
					case <-time.After(500 * time.Millisecond):
					}
				default:
					status := 503
					if mode == "401" {
						status = 401
					}
					if mode == "429" {
						status = 429
					}
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(status)
					w.Write([]byte("SECRET CODE TOKEN"))
				}
			}))
			defer s.Close()
			c := outbound.New(100 * time.Millisecond)
			defer c.CloseIdleConnections()
			a := newDingTalk("app", "SECRET", "https://porter.test/callback/dingtalk", c)
			defer a.CloseIdleConnections()
			a.tokenURL = s.URL
			_, err := a.Exchange(context.Background(), "CODE", "", "")
			if err == nil || strings.Contains(err.Error(), "SECRET") || hits.Load() != 1 || redirected.Load() != 0 {
				t.Fatal("exchange retried, redirected or disclosed input")
			}
		})
	}
}

func TestDingTalkMalformedCodesNeverReachUpstream(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer s.Close()
	c := outbound.New(time.Second)
	defer c.CloseIdleConnections()
	a := newDingTalk("app", "SECRET", "https://porter.test/callback/dingtalk", c)
	defer a.CloseIdleConnections()
	a.tokenURL = s.URL
	for _, code := range []string{"", " CODE", "CODE ", "CODE\n", strings.Repeat("x", 4097)} {
		if _, err := a.Exchange(context.Background(), code, "", ""); err == nil {
			t.Fatal("malformed code accepted")
		}
	}
	if hits.Load() != 0 {
		t.Fatal("malformed code reached upstream")
	}
}
