package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/outbound"
	"golang.org/x/oauth2"
)

// Exercise one shared adapter/config over real HTTP, including oauth2's
// automatic-auth-style rejection path. Every distinct code gets one attempt.
func TestConcurrentCodeExchangeFailuresAreSingleAttempt(t *testing.T) {
	for _, name := range []string{"github", "google", "wechat", "qq"} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			hits := map[string]int{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Error("invalid exchange form")
				}
				mu.Lock()
				hits[r.Form.Get("code")]++
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"invalid_client"}`))
			}))
			defer server.Close()
			client := outbound.New(3 * time.Second)
			defer client.CloseIdleConnections()
			exchange := outbound.Exchange(client)
			defer exchange.CloseIdleConnections()
			adapter := &OAuth{Name: name, Client: client, ExchangeClient: exchange, Config: oauth2.Config{ClientID: "app", ClientSecret: "fixture-SECRET", Endpoint: oauth2.Endpoint{TokenURL: server.URL + "/token", AuthStyle: oauth2.AuthStyleAutoDetect}}}
			const total = 16
			barrier := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(total)
			for i := 0; i < total; i++ {
				go func(index int) {
					defer wg.Done()
					<-barrier
					if _, err := adapter.Exchange(context.Background(), fmt.Sprintf("fixture-code-%d", index), "verifier", "nonce"); err == nil {
						t.Error("failed exchange succeeded")
					}
				}(i)
			}
			close(barrier)
			wg.Wait()
			mu.Lock()
			defer mu.Unlock()
			if len(hits) != total {
				t.Fatal("not every code reached the fixture once", len(hits))
			}
			for i := 0; i < total; i++ {
				if hits[fmt.Sprintf("fixture-code-%d", i)] != 1 {
					t.Fatal("authorization code was replayed")
				}
			}
		})
	}
}
