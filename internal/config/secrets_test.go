package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func save(t *testing.T, c Config, dir string) string {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "porter.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func secretFile(t *testing.T, dir, name, value string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestFileSecretsMatchInlineConfiguration(t *testing.T) {
	dir := t.TempDir()
	c := valid()
	c.StargateURL = "https://stargate.test/_auth"
	c.StargateSecret = strings.Repeat("s", 32)
	c.Operations.Key = strings.Repeat("m", 32)
	inline, err := Load(save(t, c, dir))
	if err != nil {
		t.Fatal(err)
	}
	secretFile(t, dir, "proxy", c.ProxyKey+"\r\n", 0400)
	c.ProxyKeyFile = "proxy"
	c.ProxyKey = ""
	secretFile(t, dir, "stargate", c.StargateSecret+"\n", 0600)
	c.StargateSecretFile = "stargate"
	c.StargateSecret = ""
	secretFile(t, dir, "management", c.Operations.Key, 0440)
	c.Operations.KeyFile = "management"
	c.Operations.Key = ""
	for _, name := range []string{"github", "google", "wechat", "qq"} {
		c.Providers[name] = Provider{ClientID: "app", ClientSecretFile: name + "-secret"}
		secretFile(t, dir, name+"-secret", "provider-secret", 0400)
	}
	loaded, err := Load(save(t, c, dir))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ProxyKey != inline.ProxyKey || loaded.StargateSecret != inline.StargateSecret || loaded.Operations.Key != inline.Operations.Key || loaded.Bindings[0].Revision() != inline.Bindings[0].Revision() {
		t.Fatal("secret source changed key or binding semantics")
	}
	for _, p := range loaded.Providers {
		if p.ClientSecret != "provider-secret" {
			t.Fatal("provider file unresolved")
		}
	}
	if err = loaded.Validate(); err != nil {
		t.Fatal("resolved configuration is not valid", err)
	}
	if err := os.Chmod(filepath.Join(dir, "proxy"), 0600); err != nil {
		t.Fatal(err)
	}
	secretFile(t, dir, "proxy", strings.Repeat("x", 32), 0400)
	if loaded.ProxyKey != inline.ProxyKey {
		t.Fatal("secret changed after startup")
	}
}
func TestFileSecretFailuresAreRedacted(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		mode        os.FileMode
	}{
		{"public", "SECRET", 0644}, {"group writable", "SECRET", 0660}, {"executable", "SECRET", 0700},
		{"too large", strings.Repeat("S", maxSecretSize+1), 0600}, {"empty", "", 0600},
		{"spaces", " SECRET ", 0600}, {"multiline", "SECRET\n\n", 0600}, {"invalid UTF8", string([]byte{255}), 0600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := secretFile(t, dir, "SECRET-file", tc.value, tc.mode)
			c := valid()
			p := c.Providers["github"]
			p.ClientSecret = ""
			p.ClientSecretFile = path
			c.Providers["github"] = p
			_, err := Load(save(t, c, dir))
			if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), dir) {
				t.Fatal("invalid secret accepted or disclosed", err)
			}
		})
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.ProxyKeyFile = "SECRET-missing" },
		func(c *Config) { c.StargateSecret = "SECRET"; c.StargateSecretFile = "SECRET-missing" },
		func(c *Config) { c.Operations.Key = "SECRET"; c.Operations.KeyFile = "SECRET-missing" },
		func(c *Config) {
			p := c.Providers["github"]
			p.ClientSecretFile = "SECRET-missing"
			c.Providers["github"] = p
		},
	} {
		dir := t.TempDir()
		c := valid()
		change(&c)
		_, err := Load(save(t, c, dir))
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatal("dual source accepted or disclosed", err)
		}
	}
}
func TestProjectedFilesAndNonregularSecrets(t *testing.T) {
	dir := t.TempDir()
	target := secretFile(t, dir, "target", strings.Repeat("k", 32), 0400)
	link := filepath.Join(dir, "projected")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	c := valid()
	c.ProxyKey = ""
	c.ProxyKeyFile = link
	if _, err := Load(save(t, c, dir)); err != nil {
		t.Fatal("projected secret rejected", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(link, 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := Load(save(t, c, dir)); err == nil {
		t.Fatal("FIFO accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("FIFO blocked loader")
	}
	c.ProxyKeyFile = dir
	if _, err := Load(save(t, c, dir)); err == nil {
		t.Fatal("directory accepted")
	}
}
func TestResolvedKeysKeepExistingTrustSeparation(t *testing.T) {
	dir := t.TempDir()
	c := valid()
	c.Operations.KeyFile = secretFile(t, dir, "management", c.ProxyKey, 0400)
	if _, err := Load(save(t, c, dir)); err == nil {
		t.Fatal("management key reused proxy credential")
	}
}
