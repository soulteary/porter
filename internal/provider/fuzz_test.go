package provider

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type rejectingFuzzKeySet struct{}

func (rejectingFuzzKeySet) VerifySignature(context.Context, string) ([]byte, error) {
	return nil, errors.New("untrusted fixture signature")
}

func FuzzProviderResponseSingleExchange(f *testing.F) {
	for i := uint8(0); i < 4; i++ {
		for _, body := range []string{`{}`, `not-json`, `{"access_token":"token","token_type":"Bearer","openid":"subject","client_id":"app","id":123}`, `{"access_token":"token","token_type":"Bearer","id_token":"unsigned.invalid.token"}`, `{"error":"fixture-SECRET"}`} {
			f.Add(i, uint16(200), []byte(body))
		}
		f.Add(i, uint16(401), []byte(`{"error":"invalid_client"}`))
	}
	f.Fuzz(func(t *testing.T, index uint8, status uint16, body []byte) {
		if len(body) > 1<<20 || status < 100 || status > 599 {
			t.Skip()
		}
		name := []string{"github", "google", "wechat", "qq"}[index%4]
		exchanges := 0
		client := &http.Client{Timeout: time.Second, Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host != "fixture.invalid" {
				t.Fatal("unexpected network target")
			}
			if req.URL.Path == "/token" {
				exchanges++
			}
			return &http.Response{StatusCode: int(status), Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
		})}
		a := &OAuth{Name: name, Client: client, ExchangeClient: client, identityURL: "https://fixture.invalid/user", Config: oauth2.Config{ClientID: "app", ClientSecret: "fixture-SECRET", Endpoint: oauth2.Endpoint{TokenURL: "https://fixture.invalid/token", AuthStyle: oauth2.AuthStyleAutoDetect}}, Verifier: oidc.NewVerifier("https://accounts.google.com", rejectingFuzzKeySet{}, &oidc.Config{ClientID: "app", SupportedSigningAlgs: []string{oidc.RS256}})}
		identity, err := a.Exchange(context.Background(), "fixture-CODE", "verifier", "nonce")
		if exchanges != 1 {
			t.Fatal("one-use code exchange was not single attempt", exchanges)
		}
		if err != nil && (strings.Contains(err.Error(), "fixture-SECRET") || strings.Contains(err.Error(), "fixture-CODE")) {
			t.Fatal("provider error disclosed credentials")
		}
		if err == nil && (identity.Provider != name || identity.Namespace != "app" || identity.Subject == "") {
			t.Fatal("successful exchange returned an unbound identity")
		}
		if name == "google" && err == nil {
			t.Fatal("untrusted signing key authenticated a Google identity")
		}
	})
}
