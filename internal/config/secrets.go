package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
)

const maxSecretSize = 8192

// Resolve only administrator-configured files during Load, before validation.
// Keep path references for callers; never re-resolve or reload at runtime.
func (c *Config) resolveSecrets(directory string) error {
	resolve := func(value *string, path, field string) error {
		if path == "" {
			return nil
		}
		if *value != "" {
			return errors.New(field + " and its file source are mutually exclusive")
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(directory, path)
		}
		secret, err := readSecret(path)
		if err != nil {
			return errors.New(field + " file must be a readable private regular UTF-8 file of at most 8192 bytes")
		}
		*value = secret
		return nil
	}
	if err := resolve(&c.ProxyKey, c.ProxyKeyFile, "proxy_key"); err != nil {
		return err
	}
	if err := resolve(&c.StargateSecret, c.StargateSecretFile, "stargate_secret"); err != nil {
		return err
	}
	if err := resolve(&c.Operations.Key, c.Operations.KeyFile, "operations.key"); err != nil {
		return err
	}
	// Unknown provider names are rejected by Validate; never interpolate them in
	// errors or read file paths belonging to unsupported provider definitions.
	for _, name := range []string{"github", "google", "wechat", "qq"} {
		p, ok := c.Providers[name]
		if !ok {
			continue
		}
		if err := resolve(&p.ClientSecret, p.ClientSecretFile, "providers."+name+".client_secret"); err != nil {
			return err
		}
		c.Providers[name] = p
	}
	return nil
}

func readSecret(path string) (string, error) {
	// Projected Secret mounts use symlinks. Follow the configured path once, then
	// validate and read the same descriptor. Nonblocking open prevents FIFO hangs.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	// Permit group read for a dedicated fsGroup, but no other access, executable
	// bits, or group write. 0400/0600 and 0440/0640 are supported.
	if !st.Mode().IsRegular() || st.Mode().Perm()&0137 != 0 || st.Mode().Perm()&0440 == 0 || st.Size() > maxSecretSize {
		return "", errors.New("invalid secret file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretSize+1))
	if err != nil || len(data) > maxSecretSize || !utf8.Valid(data) {
		return "", errors.New("invalid secret contents")
	}
	value := string(data)
	// Remove exactly one conventional terminal line ending, not surrounding
	// spaces or additional lines. Existing clean() validation still applies.
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
		value = strings.TrimSuffix(value, "\r")
	}
	if !clean(value) {
		return "", errors.New("invalid secret contents")
	}
	return value, nil
}
