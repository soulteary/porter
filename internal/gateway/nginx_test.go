package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/store"
)

// TestNginxTrustBoundary runs the actual template and Porter handler. Only the
// Stargate and business upstreams are simulated; request context is not fabricated.
func TestNginxTrustBoundary(t *testing.T) {
	nginx := os.Getenv("PORTER_NGINX")
	if nginx == "" {
		t.Skip("set PORTER_NGINX to run the proxy integration test")
	}
	sample := os.Getenv("PORTER_NGINX_CONFIG")
	if sample == "" {
		sample = "../../examples/nginx.conf"
	}
	template, e := os.ReadFile(sample)
	if e != nil {
		t.Fatal(e)
	}
	g, _ := fixture(t)
	g.cfg.PublicURL = "https://login.example.com"
	g.origin, _ = url.Parse(g.cfg.PublicURL)
	token := strings.Repeat("a", 43)
	if e = seedSession(g, token, store.Record{Expires: time.Now().Add(time.Hour), Provider: "github", Namespace: "app", Subject: "123"}); e != nil {
		t.Fatal(e)
	}
	var mode atomic.Int32
	var businessHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-User-Mail") != "owner@example.test" || r.Header.Get("X-Stargate-Header-Auth") != strings.Repeat("s", 32) || r.Header.Get("Cookie") != "" || r.Header.Get("Stargate-Password") != "" || r.Header.Get("Authorization") != "" {
			t.Error("invalid Stargate trust boundary")
		}
		if r.Header.Get("X-Forwarded-Host") != "login.example.com" || r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Error("lost target origin")
		}
		method, uri := r.Header.Get("X-Forwarded-Method"), r.Header.Get("X-Forwarded-Uri")
		if uri == "/sensitive?tab=one" {
			if method != "POST" {
				t.Error("lost original POST method")
			}
			w.WriteHeader(403)
			return
		}
		if uri != "/app?tab=one" || method != "GET" {
			t.Errorf("lost original target: %s %s", method, uri)
		}
		switch mode.Load() {
		case 1:
			w.WriteHeader(503)
			return
		case 2:
			w.Header().Set("X-Auth-User", "reassigned-user")
			w.Header().Set("X-Forwarded-User", "reassigned-user")
		default:
			w.Header().Set("X-Auth-User", "internal-1")
			w.Header().Set("X-Forwarded-User", "internal-1")
		}
		w.Header().Set("X-Auth-Role", "reader")
	}))
	defer upstream.Close()
	g.cfg.StargateURL = upstream.URL + "/_auth"
	g.cfg.StargateSecret = strings.Repeat("s", 32)
	porter := httptest.NewServer(g.Handler())
	defer porter.Close()
	business := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		businessHits.Add(1)
		for _, name := range []string{"X-User-Mail", "X-User-Phone", "X-Porter-User-ID", "Authorization", "X-Stargate-Header-Auth", "Stargate-Password"} {
			if r.Header.Get(name) != "" {
				t.Errorf("leaked %s to application", name)
			}
		}
		fmt.Fprintf(w, "%s:%s:%s", r.Header.Get("X-Auth-User"), r.Header.Get("X-Forwarded-User"), r.Header.Get("X-Auth-Role"))
	}))
	defer business.Close()
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certificateSource.TLS.Certificates[0]
	certificateSource.Close()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	listener.Close()
	conf := string(template)
	for old, new := range map[string]string{"porter:8083": strings.TrimPrefix(porter.URL, "http://"), "application:8080": strings.TrimPrefix(business.URL, "http://"), "listen 443 ssl;": "listen 127.0.0.1:" + port + " ssl;", "/etc/nginx/tls/fullchain.pem": certPath, "/etc/nginx/tls/privkey.pem": keyPath, "/var/log/nginx/access.log": filepath.Join(dir, "access.log"), "REPLACE_PORTER_PROXY_KEY": g.cfg.ProxyKey} {
		conf = strings.ReplaceAll(conf, old, new)
	}
	conf = "pid " + filepath.Join(dir, "nginx.pid") + ";\nerror_log stderr;\nevents {}\nhttp {\n" + conf + "\n}\n"
	configPath := filepath.Join(dir, "nginx.conf")
	if e = os.WriteFile(configPath, []byte(conf), 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(nginx, "-p", dir, "-c", configPath, "-g", "daemon off;")
	cmd.Stderr = os.Stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGQUIT)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Nginx did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, tc := range []struct {
		name, method, path string
		mode               int32
		want               int
	}{
		{"allow canonical identity", "GET", "/app?tab=one", 0, 200},
		{"original POST policy", "POST", "/sensitive?tab=one", 0, 403},
		{"reassigned contact", "GET", "/app?tab=one", 2, 403},
		{"directory unavailable", "GET", "/app?tab=one", 1, 500},
		{"private subrequest", "GET", "/_access", 0, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode.Store(tc.mode)
			before := businessHits.Load()
			r, _ := http.NewRequest(tc.method, "https://"+address+tc.path, nil)
			r.Host = "login.example.com"
			r.AddCookie(&http.Cookie{Name: g.cookieName("session"), Value: token})
			for _, name := range []string{"X-Auth-User", "X-Forwarded-User", "X-Auth-Role", "X-User-Mail", "X-Porter-User-ID", "Authorization", "X-Stargate-Header-Auth", "Stargate-Password", "X-Forwarded-Uri", "X-Forwarded-Method", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				r.Header.Set(name, "attacker")
			}
			resp, e := client.Do(r)
			if e != nil {
				t.Fatal(e)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("want %d got %d: %s", tc.want, resp.StatusCode, body)
			}
			if tc.want == 200 && string(body) != "internal-1:internal-1:reader" {
				t.Fatalf("incorrect application identity: %s", body)
			}
			if tc.want != 200 && businessHits.Load() != before {
				t.Fatal("failed request reached application")
			}
		})
	}
}
