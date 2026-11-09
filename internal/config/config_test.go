package config

import (
	"strings"
	"testing"
)

func valid() Config {
	return Config{PublicURL: "https://porter.test", LandingURL: "https://porter.test/app", ProxyKey: strings.Repeat("k", 32), Providers: map[string]Provider{"github": {ClientID: "app", ClientSecret: "secret"}}, Bindings: []Binding{{Provider: "github", Namespace: "app", Subject: "123", UserID: "u1", Mail: "owner@example.test"}}}
}
func TestValidation(t *testing.T) {
	if c := valid(); c.Validate() != nil {
		t.Fatal("valid config rejected")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.PublicURL = "http://porter.test" }, func(c *Config) { c.LandingURL = "https://evil.test" }, func(c *Config) { c.ProxyKey = "short" }, func(c *Config) { c.Bindings = append(c.Bindings, c.Bindings[0]) }, func(c *Config) { c.Bindings[0].Namespace = "other" }, func(c *Config) { c.Bindings[0].Mail = "x\r\nInjected: true" }, func(c *Config) { c.Bindings[0].Phone = "123" }, func(c *Config) { c.SessionSeconds = -1 }} {
		c := valid()
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

func TestDevelopmentAndStargateTransport(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*Config)
		want  bool
	}{
		{"remote development", func(c *Config) { c.Development = true }, false},
		{"loopback development", func(c *Config) {
			c.Development = true
			c.PublicURL = "http://127.0.0.1:8083"
			c.LandingURL = c.PublicURL + "/app"
		}, true},
		{"public development listener", func(c *Config) {
			c.Development = true
			c.PublicURL = "http://localhost:8083"
			c.LandingURL = c.PublicURL + "/app"
			c.Listen = ":8083"
		}, false},
		{"unencrypted remote Stargate", func(c *Config) {
			c.StargateURL = "http://stargate:8080/_auth"
			c.StargateSecret = strings.Repeat("s", 32)
		}, false},
		{"explicit private HTTP", func(c *Config) {
			c.StargateURL = "http://stargate:8080/_auth"
			c.StargateSecret = strings.Repeat("s", 32)
			c.AllowInsecureStargate = true
		}, true},
		{"HTTPS Stargate", func(c *Config) {
			c.StargateURL = "https://stargate.test/_auth"
			c.StargateSecret = strings.Repeat("s", 32)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.setup(&c)
			if e := c.Validate(); (e == nil) != tc.want {
				t.Fatal(e)
			}
		})
	}
}

func TestCanonicalPublicOrigin(t *testing.T) {
	c := valid()
	c.PublicURL = "https://PORTER.test:443/"
	c.LandingURL = "https://porter.test/app"
	if e := c.Validate(); e != nil || c.PublicURL != "https://porter.test" {
		t.Fatal("did not normalize browser origin", c.PublicURL, e)
	}
	c = valid()
	c.PublicURL = "https://porter.test?"
	if c.Validate() == nil {
		t.Fatal("origin with empty query delimiter accepted")
	}
}
