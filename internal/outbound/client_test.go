package outbound

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolsAreOwnedAndBounded(t *testing.T) {
	a, b := New(time.Second), New(2*time.Second)
	defer a.CloseIdleConnections()
	defer b.CloseIdleConnections()
	ta, tb := a.Transport.(*http.Transport), b.Transport.(*http.Transport)
	if ta == tb || ta == http.DefaultTransport || ta.MaxConnsPerHost != 32 || ta.ResponseHeaderTimeout != time.Second || ta.TLSClientConfig.MinVersion != tls.VersionTLS12 || ta.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("unbounded, shared or insecure transport")
	}
	exchange := Exchange(a)
	te := exchange.Transport.(*http.Transport)
	if te == ta || !te.DisableKeepAlives || te.ForceAttemptHTTP2 || te.TLSNextProto == nil || ta.DisableKeepAlives {
		t.Fatal("exchange isolation changed pooled client")
	}
}
func TestRedirectCancellationTimeoutAndTLS(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		http.Redirect(w, r, target.URL, 302)
	}))
	defer source.Close()
	client := New(100 * time.Millisecond)
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest("GET", source.URL+"?code=SECRET", nil)
	req.Header.Set("Authorization", "Bearer SECRET")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || hits.Load() != 0 {
		t.Fatal("followed redirect")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ = http.NewRequestWithContext(ctx, "GET", source.URL, nil)
	if resp, err = client.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("ignored cancellation")
	}
	start := time.Now()
	if resp, err = client.Get(source.URL + "/slow"); err == nil {
		resp.Body.Close()
		t.Fatal("ignored timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout not bounded")
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer tlsServer.Close()
	if resp, err = client.Get(tlsServer.URL); err == nil {
		resp.Body.Close()
		t.Fatal("accepted untrusted TLS")
	}
}
