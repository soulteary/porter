package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
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
			if name == "github" && (q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != oauth2.S256ChallengeFromVerifier("verifier")) {
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
							if r.Method != "POST" || r.Form.Get("client_id") != "app" || r.Form.Get("client_secret") != "secret" || r.Form.Get("redirect_uri") != "https://porter.test/callback/github" || r.Form.Get("code") != "code" || r.Form.Get("code_verifier") != "verifier" {
								t.Error("missing exchange binding")
							}
							_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
						case "wechat":
							if r.Method != "GET" || r.URL.Query().Get("grant_type") != "authorization_code" || r.URL.Query().Get("code") != "code" || r.URL.Query().Get("appid") != "app" || r.URL.Query().Get("secret") != "secret" {
								t.Error("missing WeChat credentials")
							}
							if bad {
								_, _ = w.Write([]byte(`{"errcode":40029}`))
							} else {
								_, _ = w.Write([]byte(`{"access_token":"token","openid":"wx-subject"}`))
							}
						case "qq":
							if r.Method != "GET" || r.URL.Query().Get("grant_type") != "authorization_code" || r.URL.Query().Get("code") != "code" || r.URL.Query().Get("client_id") != "app" || r.URL.Query().Get("client_secret") != "secret" || r.URL.Query().Get("redirect_uri") != "https://porter.test/callback/qq" || r.URL.Query().Get("fmt") != "json" {
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

	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"multiple audiences without azp", map[string]any{"aud": []string{"app", "other"}}, false},
		{"multiple audiences with azp", map[string]any{"aud": []string{"app", "other"}, "azp": "app"}, true},
		{"wrong azp", map[string]any{"azp": "other"}, false},
		{"empty subject", map[string]any{"sub": ""}, false},
		{"missing nonce", map[string]any{"nonce": ""}, false},
		{"wrong access token hash", map[string]any{"at_hash": "wrong"}, false},
		{"valid access token hash", map[string]any{"at_hash": accessTokenHash("token")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"iss": "https://accounts.google.com", "aud": "app", "sub": "stable-google-sub", "nonce": "nonce", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
			for key, value := range tc.claims {
				claims[key] = value
			}
			data, _ := json.Marshal(claims)
			signed, e := signer.Sign(data)
			if e != nil {
				t.Fatal(e)
			}
			raw, e = signed.CompactSerialize()
			if e != nil {
				t.Fatal(e)
			}
			_, e = a.Exchange(context.Background(), "code", "verifier", "nonce")
			if (e == nil) != tc.want {
				t.Fatal(e)
			}
		})
	}
	// A structurally valid token signed by an untrusted key must also fail.
	otherKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	otherSigner, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: otherKey}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(map[string]any{"iss": "https://accounts.google.com", "aud": "app", "sub": "forged", "nonce": "nonce", "exp": time.Now().Add(time.Hour).Unix()})
	signed, e := otherSigner.Sign(data)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = signed.CompactSerialize()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Exchange(context.Background(), "code", "verifier", "nonce"); e == nil {
		t.Fatal("accepted forged signature")
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

func accessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestGoogleAuthorization(t *testing.T) {
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://accounts.google.com/.well-known/openid-configuration" {
			t.Fatalf("unexpected request %s", r.URL)
		}
		w := httptest.NewRecorder()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://accounts.google.com", "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth", "token_endpoint": "https://oauth2.googleapis.com/token", "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs", "id_token_signing_alg_values_supported": []string{"RS256"}})
		return w.Result(), nil
	})}
	a, e := New(context.Background(), "google", config.Provider{ClientID: "app", ClientSecret: "secret"}, "https://porter.test/callback/google", client)
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(a.AuthorizationURL("state", "verifier", "nonce"))
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	if q.Get("state") != "state" || q.Get("nonce") != "nonce" || q.Get("scope") != "openid" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != oauth2.S256ChallengeFromVerifier("verifier") {
		t.Fatal("incorrect OIDC authorization parameters")
	}
}
func TestAdapterRejectsRedirectsFromDefaultClient(t *testing.T) {
	var hits int
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer destination.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer upstream.Close()
	client := upstream.Client()
	adapter, e := New(context.Background(), "wechat", config.Provider{ClientID: "app", ClientSecret: "secret"}, "https://porter.test/callback/wechat", client)
	if e != nil {
		t.Fatal(e)
	}
	a := adapter.(*OAuth)
	a.Config.Endpoint.TokenURL = upstream.URL
	if _, e = a.Exchange(context.Background(), "code", "verifier", "nonce"); e == nil || hits != 0 {
		t.Fatal("followed credential-bearing redirect")
	}
	if client.CheckRedirect != nil {
		t.Fatal("mutated caller HTTP client")
	}
}

func TestMalformedProviderResponses(t *testing.T) {
	for _, name := range []string{"github", "wechat", "qq"} {
		for _, tc := range []struct {
			name, body string
			status     int
		}{
			{"invalid JSON", "not-json", 200},
			{"provider error", `{"error":"invalid_grant","errcode":40029}`, 200},
			{"missing identity", `{"access_token":"token","token_type":"Bearer"}`, 200},
			{"trailing JSON", `{"access_token":"token","openid":"subject"} {}`, 200},
			{"oversized response", strings.Repeat(" ", 1<<20) + `{}`, 200},
			{"HTTP failure", `{"access_token":"token","openid":"subject"}`, 503},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
				}))
				defer upstream.Close()
				adapter, e := New(context.Background(), name, config.Provider{ClientID: "app", ClientSecret: "secret"}, "https://porter.test/callback/"+name, upstream.Client())
				if e != nil {
					t.Fatal(e)
				}
				a := adapter.(*OAuth)
				a.Config.Endpoint.TokenURL = upstream.URL
				a.identityURL = upstream.URL
				if _, e = a.Exchange(context.Background(), "code", "verifier", "nonce"); e == nil {
					t.Fatal("accepted malformed provider response")
				}
			})
		}
	}
}
