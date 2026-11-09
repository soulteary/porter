// Package config loads administrator-owned provider and identity configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"unicode"
)

type Provider struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
type Binding struct {
	Provider  string `json:"provider"`
	Namespace string `json:"namespace"`
	Subject   string `json:"subject"`
	UserID    string `json:"user_id"`
	Mail      string `json:"mail,omitempty"`
	Phone     string `json:"phone,omitempty"`
}
type Config struct {
	AllowInsecureStargate bool                `json:"allow_insecure_stargate,omitempty"`
	StargateURL           string              `json:"stargate_url,omitempty"`
	StargateSecret        string              `json:"stargate_secret,omitempty"`
	Listen                string              `json:"listen"`
	PublicURL             string              `json:"public_url"`
	LandingURL            string              `json:"landing_url"`
	Database              string              `json:"database"`
	ProxyKey              string              `json:"proxy_key"`
	Development           bool                `json:"development"`
	SessionSeconds        int                 `json:"session_seconds"`
	Providers             map[string]Provider `json:"providers"`
	Bindings              []Binding           `json:"bindings"`
}

func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 4<<20))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return c, errors.New("configuration must contain one JSON object")
	}
	return c, c.Validate()
}
func clean(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}
func webURL(s string, dev bool) bool {
	u, e := url.Parse(s)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	return u.Scheme == "https" || dev && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
}
func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = ":8083"
		if c.Development {
			c.Listen = "127.0.0.1:8083"
		}
	}
	if c.Database == "" {
		c.Database = "porter.db"
	}
	if c.SessionSeconds == 0 {
		c.SessionSeconds = 28800
	}
	if !webURL(c.PublicURL, c.Development) || !webURL(c.LandingURL, c.Development) {
		return errors.New("public_url and landing_url require HTTPS (loopback HTTP allowed in development)")
	}
	if c.Development {
		u, _ := url.Parse(c.PublicURL)
		host, _, e := net.SplitHostPort(c.Listen)
		if !loopback(u.Hostname()) || e != nil || !loopback(host) {
			return errors.New("development requires a loopback public URL and listener")
		}
	}
	landing, _ := url.Parse(c.LandingURL)
	public, _ := url.Parse(c.PublicURL)
	if origin(landing) != origin(public) {
		return errors.New("landing_url must share public_url origin; cross-domain sessions are not supported")
	}
	u, _ := url.Parse(c.PublicURL)
	if u.Path != "" && u.Path != "/" || (u.RawQuery != "" || u.ForceQuery) {
		return errors.New("public_url must be an origin")
	}
	c.PublicURL = origin(public)
	if len(c.ProxyKey) < 32 || !clean(c.ProxyKey) {
		return errors.New("proxy_key must contain at least 32 characters without surrounding whitespace or control characters")
	}
	if c.SessionSeconds < 60 || c.SessionSeconds > 86400 {
		return errors.New("session_seconds must be between 60 and 86400")
	}
	if (c.StargateURL == "") != (c.StargateSecret == "") {
		return errors.New("stargate_url and stargate_secret must be configured together")
	}
	if c.StargateURL != "" {
		u, e := url.Parse(c.StargateURL)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "/_auth" {
			return errors.New("stargate_url must be an HTTP(S) /_auth endpoint without credentials or query")
		}
		if u.Scheme == "http" && !loopback(u.Hostname()) && !c.AllowInsecureStargate {
			return errors.New("non-loopback HTTP Stargate requires allow_insecure_stargate")
		}
		if len(c.StargateSecret) < 32 || !clean(c.StargateSecret) {
			return errors.New("stargate_secret requires at least 32 characters")
		}
	}
	if len(c.Providers) == 0 {
		return errors.New("at least one provider is required")
	}
	for name, p := range c.Providers {
		switch name {
		case "github", "google", "wechat", "qq":
		default:
			return fmt.Errorf("unsupported provider %q", name)
		}
		if !clean(p.ClientID) || !clean(p.ClientSecret) {
			return fmt.Errorf("provider %s requires credentials", name)
		}
	}
	seen := map[string]bool{}
	for _, b := range c.Bindings {
		p, ok := c.Providers[b.Provider]
		if !ok || b.Namespace != p.ClientID || !clean(b.Subject) || !clean(b.UserID) {
			return errors.New("binding requires enabled provider, matching client namespace, subject and user_id")
		}
		if (b.Mail == "") == (b.Phone == "") {
			return errors.New("binding requires exactly one administrator-verified Warden mail or phone")
		}
		if b.Mail != "" && !clean(b.Mail) || b.Phone != "" && !clean(b.Phone) {
			return errors.New("invalid binding contact")
		}
		key := b.Provider + "\x00" + b.Namespace + "\x00" + b.Subject
		if seen[key] {
			return errors.New("duplicate external identity binding")
		}
		seen[key] = true
	}
	return nil
}
func (c Config) Resolve(provider, namespace, subject string) (Binding, bool) {
	for _, b := range c.Bindings {
		if b.Provider == provider && b.Namespace == namespace && b.Subject == subject {
			return b, true
		}
	}
	return Binding{}, false
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Revision binds a session to the exact administrator-approved identity mapping.
func (b Binding) Revision() string {
	data, _ := json.Marshal(b)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// origin uses the browser's default-port and host casing rules for Origin checks.
func origin(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host
}
