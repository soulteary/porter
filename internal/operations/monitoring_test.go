package operations

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/observe"
	version "github.com/soulteary/version-kit/v4"
)

// Alert fixtures use the exported series, including the registry's namespace.
// An explicit Registry makes metrics-kit ignore HTTPMetricsConfig.Subsystem.
func TestMonitoringMetricContract(t *testing.T) {
	c := configuration(t)
	r, err := New(c, func(context.Context) error { return nil }, version.New("test", "test", "unknown"), &logBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.Observe(context.Background(), observe.Event{Action: "login_callback", Route: "/callback/{provider}", Provider: "github", Method: "GET", Result: "failure", Reason: "provider_authentication_failed", Status: 502, Duration: 3 * time.Second})
	body := admin(r, c, "/metrics", "127.0.0.1:1234", "").Body.String()
	for _, series := range []string{"porter_audit_dropped_total", "porter_audit_write_failures_total", "porter_auth_events_total", "porter_request_duration_seconds_bucket", "porter_request_duration_seconds_count", `path="/callback/{provider}"`, `reason="provider_authentication_failed"`} {
		if !strings.Contains(body, series) {
			t.Fatalf("missing monitoring series or bounded label: %s", series)
		}
	}
}
