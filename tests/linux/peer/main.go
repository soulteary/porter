// Test-only HTTP peer for the isolated Linux acceptance network.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var client = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func fail() { panic("Linux acceptance peer failed") }
func request(target, method, token, kind string) int {
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		fail()
	}
	req.Host = "porter.test"
	req.Header.Set("Origin", "https://porter.test")
	if kind == "management" {
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("m", 32))
	} else if kind == "transaction" {
		req.AddCookie(&http.Cookie{Name: "__Host-porter_transaction", Value: strings.Repeat(token, 43)})
	} else if token != "" {
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("p", 32))
		req.AddCookie(&http.Cookie{Name: "__Host-porter_session", Value: strings.Repeat(token, 43)})
	}
	response, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	return response.StatusCode
}
func main() {
	if len(os.Args) < 3 {
		fail()
	}
	if os.Args[1] == "request" {
		if len(os.Args) != 6 {
			fail()
		}
		json.NewEncoder(os.Stdout).Encode(map[string]int{"status": request(os.Args[2], os.Args[3], os.Args[4], os.Args[5])})
		return
	}
	if os.Args[1] != "load" || len(os.Args) != 3 {
		fail()
	}
	begin := time.Now()
	var wg sync.WaitGroup
	jobs := make(chan struct{})
	samples := make(chan float64, 200)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				started := time.Now()
				if request(os.Args[2], "GET", "C", "session") != 200 {
					samples <- -1
					continue
				}
				samples <- float64(time.Since(started)) / float64(time.Millisecond)
			}
		}()
	}
	for i := 0; i < 200; i++ {
		time.Sleep(time.Until(begin.Add(time.Duration(i) * 100 * time.Millisecond)))
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()
	close(samples)
	values := make([]float64, 0, 200)
	for sample := range samples {
		if sample < 0 {
			fail()
		}
		values = append(values, sample)
	}
	if len(values) != 200 {
		fail()
	}
	sort.Float64s(values)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"requests": 200, "offered_qps": 10, "duration_seconds": time.Since(begin).Seconds(), "p50_ms": (values[99] + values[100]) / 2, "p95_ms": values[189], "p99_ms": values[197]})
}
