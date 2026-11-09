// Package outbound owns Porter's HTTP transports. It never enables kit retries,
// request logging, or trace propagation on credential-bearing requests.
package outbound

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	httpkit "github.com/soulteary/http-kit/v2"
)

// New creates an independently owned, bounded connection pool. Destinations
// remain fixed by provider code or administrator configuration, not browser input.
func New(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
		MaxIdleConns:      64, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 32,
		IdleConnTimeout: 60 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: timeout, ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	kit, err := httpkit.NewClient(&httpkit.Options{Timeout: timeout, Transport: transport})
	if err != nil {
		panic("invalid static outbound HTTP options")
	}
	client := kit.GetHTTPClient()
	client.CheckRedirect = noRedirect
	return client
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Exchange isolates one-use code exchanges from pooled requests. In addition to
// avoiding kit retries, disable connection reuse and HTTP/2: net/http can replay
// an idempotent GET on a failed reused connection or retry an HTTP/2 stream.
// WeChat and QQ encode one-use authorization codes in GET requests.
func Exchange(source *http.Client) *http.Client {
	copy := *source
	copy.CheckRedirect = noRedirect
	transport := source.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if standard, ok := transport.(*http.Transport); ok {
		single := standard.Clone()
		single.DisableKeepAlives = true
		single.Protocols = new(http.Protocols)
		single.Protocols.SetHTTP1(true)
		single.ForceAttemptHTTP2 = false
		single.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		if single.TLSClientConfig != nil {
			single.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
		copy.Transport = single
	} else {
		// A wrapper may retry inside RoundTrip; no client option can prevent that.
		// Fail closed instead of delegating a one-use code to an unknown transport.
		copy.Transport = rejectedExchangeTransport{}
	}
	copy.Jar = nil // Exchanges do not inherit ambient browser/cookie state.
	return &copy
}

type rejectedExchangeTransport struct{}

func (rejectedExchangeTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unsupported authorization exchange transport")
}
