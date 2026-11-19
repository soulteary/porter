package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/soulteary/porter/internal/outbound"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestDingTalkConcurrentCodesAreSingleAttempt(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid request")
		}
		mu.Lock()
		hits[body["code"]]++
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	client := outbound.New(3 * time.Second)
	defer client.CloseIdleConnections()
	adapter := newDingTalk("app", "SECRET", "https://porter.test/callback/dingtalk", client)
	defer adapter.CloseIdleConnections()
	adapter.tokenURL = server.URL
	var ready, done sync.WaitGroup
	const count = 16
	ready.Add(count)
	done.Add(count)
	start := make(chan struct{})
	for i := 0; i < count; i++ {
		go func(i int) {
			defer done.Done()
			ready.Done()
			<-start
			if _, err := adapter.Exchange(context.Background(), fmt.Sprintf("code-%d", i), "", ""); err == nil {
				t.Error("failed exchange succeeded")
			}
		}(i)
	}
	ready.Wait()
	close(start)
	done.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != count {
		t.Fatal("missing exchanges")
	}
	for i := 0; i < count; i++ {
		if hits[fmt.Sprintf("code-%d", i)] != 1 {
			t.Fatal("authorization code replayed")
		}
	}
}
