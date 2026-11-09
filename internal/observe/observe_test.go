package observe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type recorder struct{ events []Event }

func (r *recorder) Observe(_ context.Context, e Event) { r.events = append(r.events, e) }
func TestPrivacyAndUnchangedResponse(t *testing.T) {
	observer := &recorder{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "porter_session=SECRET" {
			t.Fatal("request changed")
		}
		Detail(r, "invalid_transaction", "")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Error(w, "original error", 400)
	})
	r := httptest.NewRequest("GET", "https://porter.test/callback/github?state=SECRET&code=SECRET", nil)
	r.Header.Set("Cookie", "porter_session=SECRET")
	r.Header.Set("Authorization", "Bearer SECRET")
	r.Header.Set("User-Agent", "SECRET")
	r.Header.Set("X-Request-ID", "SECRET")
	w := httptest.NewRecorder()
	Wrap(next, observer).ServeHTTP(w, r)
	if w.Code != 400 || w.Body.String() != "original error\n" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("response changed")
	}
	if len(observer.events) != 1 {
		t.Fatal(observer.events)
	}
	e := observer.events[0]
	if e.Route != "/callback/{provider}" || e.Provider != "github" || e.Reason != "invalid_transaction" || len(e.RequestID) != 32 || e.RequestID == "SECRET" || e.Result != "failure" {
		t.Fatal(e)
	}
	if strings.Contains(e.Route+e.RequestID+e.UserID+e.Method+e.Reason, "SECRET") {
		t.Fatal("request data escaped")
	}
}
func TestLabelsAreBounded(t *testing.T) {
	observer := &recorder{}
	h := Wrap(http.NotFoundHandler(), observer)
	for _, path := range []string{"/arbitrary-SECRET", "/callback/SECRET", "/login/github/SECRET"} {
		r := httptest.NewRequest("SECRET", "https://porter.test"+path, nil)
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	for _, e := range observer.events {
		if e.Route != "other" || e.Provider != "none" || e.Method != "OTHER" {
			t.Fatal(e)
		}
	}
}
