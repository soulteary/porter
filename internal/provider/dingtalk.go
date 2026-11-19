package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/soulteary/porter/internal/outbound"
)

// DingTalk uses JSON token requests and an application-scoped openId. It never
// persists tokens or substitutes directory userId/unionId for that identifier.
type DingTalk struct {
	clientID, secret, callback string
	client                     *http.Client
	tokenURL, userURL          string
}

func newDingTalk(id, secret, callback string, source *http.Client) *DingTalk {
	return &DingTalk{id, secret, callback, outbound.Exchange(source), "https://api.dingtalk.com/v1.0/oauth2/userAccessToken", "https://api.dingtalk.com/v1.0/contact/users/me"}
}
func (a *DingTalk) CloseIdleConnections() { a.client.CloseIdleConnections() }
func (a *DingTalk) AuthorizationURL(state, _, _ string) string {
	q := url.Values{"client_id": {a.clientID}, "redirect_uri": {a.callback}, "response_type": {"code"}, "scope": {"openid"}, "prompt": {"consent"}, "state": {state}}
	return "https://login.dingtalk.com/oauth2/auth?" + q.Encode()
}
func (a *DingTalk) Exchange(ctx context.Context, code, _, _ string) (Identity, error) {
	id := Identity{Provider: "dingtalk", Namespace: a.clientID}
	failure := errors.New("DingTalk authentication failed")
	raw, _ := json.Marshal(map[string]string{"clientId": a.clientID, "clientSecret": a.secret, "code": code, "grantType": "authorization_code"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.tokenURL, bytes.NewReader(raw))
	if err != nil {
		return id, failure
	}
	req.Header.Set("Content-Type", "application/json")
	var token struct {
		AccessToken string `json:"accessToken"`
	}
	if a.read(req, &token) != nil || !dingValue(token.AccessToken) {
		return id, failure
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, a.userURL, nil)
	if err != nil {
		return id, failure
	}
	req.Header.Set("x-acs-dingtalk-access-token", token.AccessToken)
	var user struct {
		OpenID string `json:"openId"`
	}
	if a.read(req, &user) != nil || !dingValue(user.OpenID) {
		return id, failure
	}
	id.Subject = user.OpenID
	return id, nil
}
func dingValue(v string) bool {
	return v != "" && len(v) <= 4096 && strings.TrimSpace(v) == v && strings.IndexFunc(v, unicode.IsControl) < 0
}
func (a *DingTalk) read(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "porter")
	resp, err := a.client.Do(req)
	if err != nil {
		return errors.New("upstream unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("upstream rejected request")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return errors.New("invalid response size")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if dec.Decode(out) != nil {
		return errors.New("invalid response")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("trailing response")
	}
	return nil
}
