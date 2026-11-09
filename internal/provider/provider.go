// Package provider implements upstream login protocols. It does not grant access.
package provider

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/outbound"
	"golang.org/x/oauth2"
)

type Identity struct{ Provider, Namespace, Subject string }
type Adapter interface {
	AuthorizationURL(state, verifier, nonce string) string
	Exchange(context.Context, string, string, string) (Identity, error)
}
type OAuth struct {
	Name           string
	Config         oauth2.Config
	Client         *http.Client
	ExchangeClient *http.Client
	Verifier       *oidc.IDTokenVerifier
	identityURL    string
}

func New(ctx context.Context, name string, p config.Provider, callback string, client *http.Client) (Adapter, error) {
	// Adapter safety must not depend on the caller's redirect policy.
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if copy.Timeout <= 0 || copy.Timeout > 10*time.Second {
		copy.Timeout = 10 * time.Second
	}
	client = &copy
	a := &OAuth{Name: name, Client: client, ExchangeClient: outbound.Exchange(client), Config: oauth2.Config{ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURL: callback}}
	switch name {
	case "github":
		a.Config.Endpoint = oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", AuthStyle: oauth2.AuthStyleInParams}
		a.identityURL = "https://api.github.com/user"
	case "google":
		ctx = oidc.ClientContext(ctx, client)
		p, e := oidc.NewProvider(ctx, "https://accounts.google.com")
		if e != nil {
			a.CloseIdleConnections()
			return nil, errors.New("Google discovery failed")
		}
		a.Config.Endpoint = p.Endpoint()
		a.Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
		a.Config.Scopes = []string{oidc.ScopeOpenID}
		a.Verifier = p.Verifier(&oidc.Config{ClientID: a.Config.ClientID, SupportedSigningAlgs: []string{oidc.RS256}})
	case "wechat":
		a.Config.Endpoint = oauth2.Endpoint{AuthURL: "https://open.weixin.qq.com/connect/qrconnect", TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token"}
	case "qq":
		a.Config.Endpoint = oauth2.Endpoint{AuthURL: "https://graph.qq.com/oauth2.0/authorize", TokenURL: "https://graph.qq.com/oauth2.0/token"}
		a.Config.Scopes = []string{"get_user_info"}
		a.identityURL = "https://graph.qq.com/oauth2.0/me"
	default:
		return nil, errors.New("unsupported provider")
	}
	return a, nil
}
func (a *OAuth) AuthorizationURL(state, verifier, nonce string) string {
	if a.Name == "wechat" {
		q := url.Values{"appid": {a.Config.ClientID}, "redirect_uri": {a.Config.RedirectURL}, "response_type": {"code"}, "scope": {"snsapi_login"}, "state": {state}}
		return a.Config.Endpoint.AuthURL + "?" + q.Encode() + "#wechat_redirect"
	}
	opts := []oauth2.AuthCodeOption{}
	if a.Name == "github" || a.Name == "google" {
		opts = append(opts, oauth2.S256ChallengeOption(verifier))
	}
	if a.Name == "google" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
	}
	return a.Config.AuthCodeURL(state, opts...)
}
func (a *OAuth) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	id := Identity{Provider: a.Name, Namespace: a.Config.ClientID}
	if a.Name == "wechat" {
		q := url.Values{"appid": {a.Config.ClientID}, "secret": {a.Config.ClientSecret}, "code": {code}, "grant_type": {"authorization_code"}}
		var r struct {
			AccessToken string `json:"access_token"`
			OpenID      string `json:"openid"`
			ErrCode     int    `json:"errcode"`
		}
		if e := a.getJSONWith(ctx, a.exchangeClient(), a.Config.Endpoint.TokenURL+"?"+q.Encode(), "", &r); e != nil || r.ErrCode != 0 || r.AccessToken == "" || r.OpenID == "" {
			return id, errors.New("WeChat exchange failed")
		}
		id.Subject = r.OpenID
		return id, nil
	}
	if a.Name == "qq" {
		q := url.Values{"grant_type": {"authorization_code"}, "client_id": {a.Config.ClientID}, "client_secret": {a.Config.ClientSecret}, "code": {code}, "redirect_uri": {a.Config.RedirectURL}, "fmt": {"json"}}
		var token struct {
			AccessToken string          `json:"access_token"`
			Error       json.RawMessage `json:"error"`
		}
		if e := a.getJSONWith(ctx, a.exchangeClient(), a.Config.Endpoint.TokenURL+"?"+q.Encode(), "", &token); e != nil || len(token.Error) > 0 || token.AccessToken == "" {
			return id, errors.New("QQ exchange failed")
		}
		q = url.Values{"access_token": {token.AccessToken}, "fmt": {"json"}}
		var user struct {
			ClientID string          `json:"client_id"`
			OpenID   string          `json:"openid"`
			Error    json.RawMessage `json:"error"`
		}
		if e := a.getJSON(ctx, a.identityURL+"?"+q.Encode(), "", &user); e != nil || len(user.Error) > 0 || user.ClientID != a.Config.ClientID || user.OpenID == "" {
			return id, errors.New("QQ identity failed")
		}
		id.Subject = user.OpenID
		return id, nil
	}
	opts := []oauth2.AuthCodeOption{oauth2.VerifierOption(verifier)}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.exchangeClient())
	token, e := a.Config.Exchange(ctx, code, opts...)
	if e != nil || token == nil || token.AccessToken == "" {
		return id, errors.New("token exchange failed")
	}
	if a.Name == "google" {
		raw, ok := token.Extra("id_token").(string)
		if !ok {
			return id, errors.New("missing ID token")
		}
		t, e := a.Verifier.Verify(oidc.ClientContext(ctx, a.Client), raw)
		if e != nil {
			return id, errors.New("invalid ID token")
		}
		if nonce == "" || subtle.ConstantTimeCompare([]byte(t.Nonce), []byte(nonce)) != 1 || t.Subject == "" {
			return id, errors.New("invalid ID token nonce or subject")
		}
		if t.AccessTokenHash != "" {
			if e = t.VerifyAccessToken(token.AccessToken); e != nil {
				return id, errors.New("invalid access token hash")
			}
		}
		var claims struct {
			AZP string `json:"azp"`
		}
		if e = t.Claims(&claims); e != nil {
			return id, errors.New("invalid ID token claims")
		}
		if (len(t.Audience) > 1 && claims.AZP == "") || (claims.AZP != "" && claims.AZP != a.Config.ClientID) {
			return id, errors.New("invalid authorized party")
		}
		id.Subject = t.Subject
		return id, nil
	}
	var user struct {
		ID json.Number `json:"id"`
	}
	if e = a.getJSON(ctx, a.identityURL, token.AccessToken, &user); e != nil {
		return id, errors.New("GitHub identity failed")
	}
	n, e := strconv.ParseInt(user.ID.String(), 10, 64)
	if e != nil || n <= 0 {
		return id, errors.New("invalid GitHub user ID")
	}
	id.Subject = strconv.FormatInt(n, 10)
	return id, nil
}
func (a *OAuth) CloseIdleConnections() {
	a.Client.CloseIdleConnections()
	if a.ExchangeClient != nil {
		a.ExchangeClient.CloseIdleConnections()
	}
}
func (a *OAuth) exchangeClient() *http.Client {
	if a.ExchangeClient != nil {
		return a.ExchangeClient
	}
	return outbound.Exchange(a.Client) // Keep hand-constructed adapters fail-closed too.
}
func (a *OAuth) getJSON(ctx context.Context, endpoint, token string, out any) error {
	return a.getJSONWith(ctx, a.Client, endpoint, token, out)
}
func (a *OAuth) getJSONWith(ctx context.Context, client *http.Client, endpoint, token string, out any) error {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if e != nil {
		return errors.New("invalid upstream request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "porter")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, e := client.Do(req)
	if e != nil {
		return errors.New("upstream request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return errors.New("invalid upstream response size")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	if e = d.Decode(out); e != nil {
		return errors.New("invalid upstream JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("invalid trailing upstream data")
	}
	return nil
}
