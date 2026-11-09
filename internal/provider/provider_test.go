package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/soulteary/porter/internal/config"
	"golang.org/x/oauth2"
)

func TestAuthorization(t *testing.T) {
	for _, name := range []string{"github", "wechat", "qq"} {
		t.Run(name, func(t *testing.T) {
			a, e := New(context.Background(), name, config.Provider{ClientID: "app", ClientSecret: "secret"}, "https://porter.test/callback/"+name, http.DefaultClient)
			if e != nil {
				t.Fatal(e)
			}
			u, e := url.Parse(a.AuthorizationURL("state", "verifier", "nonce"))
			if e != nil {
				t.Fatal(e)
			}
			q := u.Query()
			if q.Get("state") != "state" || q.Get("redirect_uri") != "https://porter.test/callback/"+name {
				t.Fatal("missing request binding")
			}
			if name == "github" && (q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "") {
				t.Fatal("missing PKCE")
			}
			if name == "wechat" && (q.Get("appid") != "app" || q.Get("scope") != "snsapi_login" || u.Fragment != "wechat_redirect") {
				t.Fatal("invalid WeChat request")
			}
		})
	}
}
func TestExchanges(t *testing.T) {
	for _, name := range []string{"github", "wechat", "qq"} {
		for _, bad := range []bool{false, true} {
			t.Run(name+map[bool]string{true: "/invalid", false: "/valid"}[bad], func(t *testing.T) {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if r.URL.Path == "/token" {
						switch name {
						case "github":
							_ = r.ParseForm()
							if r.Form.Get("code") != "code" || r.Form.Get("code_verifier") != "verifier" {
								t.Error("missing exchange binding")
							}
							_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
						case "wechat":
							if r.URL.Query().Get("appid") != "app" || r.URL.Query().Get("secret") != "secret" {
								t.Error("missing WeChat credentials")
							}
							if bad {
								_, _ = w.Write([]byte(`{"errcode":40029}`))
							} else {
								_, _ = w.Write([]byte(`{"access_token":"token","openid":"wx-subject"}`))
							}
						case "qq":
							if r.URL.Query().Get("fmt") != "json" {
								t.Error("missing JSON format")
							}
							_, _ = w.Write([]byte(`{"access_token":"token"}`))
						}
						return
					}
					if name == "github" {
						if r.Header.Get("Authorization") != "Bearer token" {
							t.Error("missing bearer")
						}
						if bad {
							_, _ = w.Write([]byte(`{"id":0}`))
						} else {
							_, _ = w.Write([]byte(`{"id":123,"login":"mutable-name"}`))
						}
						return
					}
					if bad {
						_, _ = w.Write([]byte(`{"client_id":"other-app","openid":"qq-subject"}`))
					} else {
						_, _ = w.Write([]byte(`{"client_id":"app","openid":"qq-subject"}`))
					}
				}))
				defer s.Close()
				adapter, e := New(context.Background(), name, config.Provider{ClientID: "app", ClientSecret: "secret"}, "https://porter.test/callback/"+name, s.Client())
				if e != nil {
					t.Fatal(e)
				}
				a := adapter.(*OAuth)
				a.Config.Endpoint.TokenURL = s.URL + "/token"
				a.identityURL = s.URL + "/user"
				id, e := a.Exchange(context.Background(), "code", "verifier", "nonce")
				if bad {
					if e == nil {
						t.Fatal("accepted invalid identity")
					}
					return
				}
				if e != nil || id.Provider != name || id.Namespace != "app" || id.Subject == "" {
					t.Fatalf("identity=%+v error=%v", id, e)
				}
			})
		}
	}
}
func TestGoogleSignedTokens(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if e != nil {
		t.Fatal(e)
	}
	var raw string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/keys" {
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "token", "token_type": "Bearer", "id_token": raw})
	}))
	defer s.Close()
	ctx := oidc.ClientContext(context.Background(), s.Client())
	a := &OAuth{Name: "google", Client: s.Client(), Config: oauth2.Config{ClientID: "app", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: s.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}}, Verifier: oidc.NewVerifier("https://accounts.google.com", oidc.NewRemoteKeySet(ctx, s.URL+"/keys"), &oidc.Config{ClientID: "app"})}
	for _, tc := range []struct {
		name, issuer, aud, nonce string
		expired                  bool
		want                     bool
	}{
		{"valid", "https://accounts.google.com", "app", "nonce", false, true},
		{"issuer", "https://evil.test", "app", "nonce", false, false},
		{"audience", "https://accounts.google.com", "other", "nonce", false, false},
		{"nonce", "https://accounts.google.com", "app", "wrong", false, false},
		{"expired", "https://accounts.google.com", "app", "nonce", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp := time.Now().Add(time.Hour)
			if tc.expired {
				exp = time.Now().Add(-time.Hour)
			}
			b, _ := json.Marshal(map[string]any{"iss": tc.issuer, "aud": tc.aud, "sub": "stable-google-sub", "nonce": tc.nonce, "exp": exp.Unix(), "iat": time.Now().Unix()})
			signed, e := signer.Sign(b)
			if e != nil {
				t.Fatal(e)
			}
			raw, e = signed.CompactSerialize()
			if e != nil {
				t.Fatal(e)
			}
			id, e := a.Exchange(context.Background(), "code", "verifier", "nonce")
			if (e == nil) != tc.want {
				t.Fatalf("unexpected result %v", e)
			}
			if tc.want && id.Subject != "stable-google-sub" {
				t.Fatal(id)
			}
		})
	}
	raw = "unsigned.invalid.token"
	if _, e = a.Exchange(context.Background(), "code", "verifier", "nonce"); e == nil {
		t.Fatal("accepted invalid signature")
	}
}
func TestUpstreamErrorIsRedacted(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.test/?access_token=SECRET", 302)
	}))
	defer s.Close()
	a := &OAuth{Client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	var out any
	e := a.getJSON(context.Background(), s.URL+"?secret=SECRET", "", &out)
	if e == nil || strings.Contains(e.Error(), "SECRET") {
		t.Fatal(e)
	}
}
