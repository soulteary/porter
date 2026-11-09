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
