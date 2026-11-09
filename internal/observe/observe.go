// Package observe defines bounded, non-secret operational events.
package observe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

type Event struct {
	Action, Route, Method, Provider, Result, Reason, RequestID, UserID string
	Status                                                             int
	Duration                                                           time.Duration
}
type Observer interface{ Observe(context.Context, Event) }
type state struct{ reason, userID string }
type contextKey struct{}

// Detail accepts only application-owned reasons and internal user IDs. It never
// accepts a URL, external subject, token, cookie or upstream error.
func Detail(r *http.Request, reason, userID string) {
	if s, ok := r.Context().Value(contextKey{}).(*state); ok {
		if reason != "" {
			s.reason = reason
		}
		if userID != "" {
			s.userID = userID
		}
	}
}

func Wrap(next http.Handler, o Observer) http.Handler {
	if o == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action, route, provider := classify(r.URL.Path)
		var entropy [16]byte
		id := "unavailable"
		if _, e := rand.Read(entropy[:]); e == nil {
			id = hex.EncodeToString(entropy[:])
		}
		w.Header().Set("X-Request-ID", id) // Never trust an incoming correlation ID.
		s := &state{}
		r = r.WithContext(context.WithValue(r.Context(), contextKey{}, s))
		capture := &response{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(capture, r)
		status := capture.status
		if status == 0 {
			status = 200
		}
		result, reason := "success", "ok"
		if status >= 400 {
			result = "failure"
			switch status {
			case 400:
				reason = "invalid_request"
			case 401:
				reason = "unauthorized"
			case 403:
				reason = "forbidden"
			case 404:
				reason = "not_found"
			case 405:
				reason = "method_not_allowed"
			case 429:
				reason = "rate_limited"
			case 502, 503, 504:
				reason = "dependency_failure"
			default:
				reason = "internal_error"
			}
		}
		if s.reason != "" {
			reason = s.reason
		}
		method := r.Method
		switch method {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		default:
			method = "OTHER"
		}
		o.Observe(r.Context(), Event{Action: action, Route: route, Method: method, Provider: provider, Result: result, Reason: reason, RequestID: id, UserID: s.userID, Status: status, Duration: time.Since(start)})
	})
}
func classify(path string) (string, string, string) {
	switch path {
	case "/login":
		return "login_page", "/login", "none"
	case "/auth":
		return "access_check", "/auth", "none"
	case "/identity":
		return "identity_check", "/identity", "none"
	case "/logout":
		return "logout", "/logout", "none"
	case "/healthz":
		return "liveness", "/healthz", "none"
	}
	for _, prefix := range []string{"/login/", "/callback/"} {
		if name, ok := strings.CutPrefix(path, prefix); ok {
			switch name {
			case "github", "google", "wechat", "qq":
				action := "login_start"
				if prefix == "/callback/" {
					action = "login_callback"
				}
				return action, strings.TrimSuffix(prefix, "/") + "/{provider}", name
			}
		}
	}
	return "other", "other", "none"
}

type response struct {
	http.ResponseWriter
	status int
}

func (w *response) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *response) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (w *response) Unwrap() http.ResponseWriter { return w.ResponseWriter }
