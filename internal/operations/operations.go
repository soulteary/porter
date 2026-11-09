// Package operations composes the shared kits without owning authentication state.
package operations

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	audit "github.com/soulteary/audit-kit/v2"
	health "github.com/soulteary/health-kit/v4"
	logger "github.com/soulteary/logger-kit/v3"
	metrics "github.com/soulteary/metrics-kit/v3"
	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/observe"
	version "github.com/soulteary/version-kit/v4"
	versionhttp "github.com/soulteary/version-kit/v4/httpadapter"
)

type Runtime struct {
	auditLifecycle              sync.RWMutex
	closed                      bool
	closeErr                    error
	Log                         *logger.Logger
	registry                    *metrics.Registry
	httpMetrics                 *metrics.HTTPMetrics
	events                      *prometheus.CounterVec
	auditDropped, auditFailed   prometheus.Counter
	audit                       *audit.Logger
	readiness                   *health.Aggregator
	draining, maintenanceFailed atomic.Bool
}

func New(c config.Config, check func(context.Context) error, info *version.Info, output io.Writer) (*Runtime, error) {
	storage, e := openAudit(c.Operations.AuditFile, c.Database)
	if e != nil {
		return nil, e
	}
	return newRuntime(c, check, info, output, storage), nil
}
func newRuntime(c config.Config, check func(context.Context) error, info *version.Info, output io.Writer, storage audit.Storage) *Runtime {
	level, _ := logger.ParseLevel(c.Operations.LogLevel)
	log := logger.New(logger.Config{Level: level, Output: output, Format: logger.FormatJSON, ServiceName: "porter", ServiceVersion: info.Version})
	reg := metrics.NewRegistry("porter")
	r := &Runtime{Log: log, registry: reg}
	r.httpMetrics = metrics.NewHTTPMetrics(metrics.HTTPMetricsConfig{Registry: reg, Namespace: "porter", Subsystem: "http"})
	r.events = reg.Counter("auth_events_total").Help("Authentication outcomes with bounded operational labels.").Labels("action", "provider", "result", "reason").BuildVec()
	r.auditDropped = reg.Counter("audit_dropped_total").Help("Audit records rejected by the bounded queue.").Build()
	r.auditFailed = reg.Counter("audit_write_failures_total").Help("Audit records that failed to persist.").Build()
	ac := audit.DefaultConfig()
	ac.Writer = &audit.WriterConfig{QueueSize: c.Operations.AuditQueueSize, Workers: 1, StopTimeout: 5 * time.Second}
	ac.OnEnqueueFailed = func(*audit.Record) { r.auditDropped.Inc() }
	ac.OnWriteFailed = func(*audit.Record, error) { r.auditFailed.Inc(); r.Log.Error().Msg("audit_write_failed") }
	r.audit = audit.NewLoggerWithWriter(redactedStorage{storage}, ac)
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: "porter", Name: "audit_queue_length", Help: "Audit records waiting for a writer."}, func() float64 {
		stats := r.audit.GetStats()
		if stats == nil {
			return 0
		}
		return float64(stats.QueueLength)
	}))
	timeout := time.Duration(c.Operations.ProbeTimeoutSeconds) * time.Second
	hc := health.DefaultConfig().WithServiceName("porter").WithTimeout(timeout)
	hc.CriticalChecks = []string{"lifecycle", "storage", "stargate"}
	r.readiness = health.NewAggregator(hc)
	r.readiness.AddChecker(health.NewCustomChecker("lifecycle", func(context.Context) error {
		if r.draining.Load() {
			return errors.New("service draining")
		}
		return nil
	}).WithTimeout(timeout))
	// A blocked bbolt read may outlive its context. One outstanding probe is
	// allowed, so repeated readiness requests cannot accumulate blocked readers.
	gate := make(chan struct{}, 1)
	r.readiness.AddChecker(health.NewCustomChecker("storage", func(ctx context.Context) error {
		if r.maintenanceFailed.Load() {
			return errors.New("storage maintenance failed")
		}
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		default:
			return errors.New("storage probe busy")
		}
		if e := check(ctx); e != nil {
			return errors.New("storage unavailable")
		}
		return nil
	}).WithTimeout(timeout))
	if c.StargateURL != "" {
		r.readiness.AddChecker(health.NewCustomChecker("stargate", func(ctx context.Context) error { return CheckStargate(ctx, c.StargateURL, timeout) }).WithTimeout(timeout))
	} else {
		r.readiness.AddChecker(health.NewDisabledChecker("stargate").WithMessage("identity-only mode"))
	}
	return r
}

func (r *Runtime) Observe(ctx context.Context, e observe.Event) {
	r.httpMetrics.RecordRequest(e.Method, e.Route, strconv.Itoa(e.Status), e.Duration)
	if e.Action == "other" || e.Action == "liveness" || e.Action == "login_page" {
		return
	}
	r.events.WithLabelValues(e.Action, e.Provider, e.Result, e.Reason).Inc()
	entry := r.Log.Debug()
	if e.Action == "login_start" || e.Action == "login_callback" || e.Action == "logout" {
		entry = r.Log.Info()
	}
	if e.Result == "failure" {
		entry = r.Log.Warn()
	}
	entry.Str("action", e.Action).Str("provider", e.Provider).Str("result", e.Result).Str("reason", e.Reason).Str("request_id", e.RequestID).Int("status", e.Status).Int64("duration_ms", e.Duration.Milliseconds()).Msg("authentication_request")
	kind := audit.EventType("")
	switch e.Action {
	case "login_start":
		if e.Result == "success" {
			kind = "login_started"
		} else {
			kind = audit.EventLoginFailed
		}
	case "login_callback":
		if e.Result == "success" {
			kind = audit.EventLoginSuccess
		} else {
			kind = audit.EventLoginFailed
		}
	case "logout":
		if e.Result == "success" {
			kind = audit.EventLogout
		} else {
			kind = "logout_failed"
		}
	case "access_check", "identity_check":
		if e.Result == "failure" {
			kind = audit.EventAccessDenied
		}
	}
	if e.Status == 429 {
		kind = audit.EventRateLimited
	}
	if kind == "" {
		return
	}
	result := audit.ResultSuccess
	if e.Result != "success" {
		result = audit.ResultFailure
	}
	record := audit.NewRecord(kind, result).WithUserID(e.UserID).WithProvider(e.Provider, "").WithRequestID(e.RequestID).WithReason(e.Reason).WithResource(e.Route).WithDuration(e.Duration.Milliseconds()).WithMetadata("action", e.Action).WithMetadata("status", e.Status)
	r.auditLifecycle.RLock()
	defer r.auditLifecycle.RUnlock()
	if r.closed {
		r.auditDropped.Inc()
		return
	}
	r.audit.Log(ctx, record)
}
func (r *Runtime) Drain() { r.draining.Store(true) }
func (r *Runtime) Maintenance(err error) {
	r.maintenanceFailed.Store(err != nil)
	if err != nil {
		r.Log.Error().Msg("storage_maintenance_failed")
	}
}
func (r *Runtime) Close() error {
	r.Drain()
	r.auditLifecycle.Lock()
	defer r.auditLifecycle.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	r.closeErr = r.audit.Stop()
	return r.closeErr
}

// Handler is served only by the separate management listener. It cannot perform
// login, exchange a provider code, or read an identity/session.
func (r *Runtime) Handler(c config.Config, info *version.Info) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", http.HandlerFunc(health.LivenessHandler("porter")))
	mux.Handle("GET /readyz", http.HandlerFunc(health.ReadinessHandler(r.readiness)))
	mux.Handle("GET /metrics", metrics.NewHandler(metrics.HandlerOpts{Registry: r.registry, Timeout: 3, MaxRequestsInFlight: 4}))
	mux.Handle("GET /version", versionhttp.Handler(version.HandlerConfig{Info: info, IncludeBuildDetails: true}))
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if c.Operations.Key != "" {
			if subtle.ConstantTimeCompare([]byte(req.Header.Get("Authorization")), []byte("Bearer "+c.Operations.Key)) != 1 {
				http.Error(w, "unauthorized", 401)
				return
			}
		} else {
			host, _, err := net.SplitHostPort(req.RemoteAddr)
			ip := net.ParseIP(host)
			if err != nil || ip == nil || !ip.IsLoopback() || !loopbackHost(req.Host) {
				http.Error(w, "loopback management access required", 403)
				return
			}
		}
		mux.ServeHTTP(w, req)
	})
}

// CheckStargate probes readiness, not /_auth. It sends no application credential,
// cookie, identity or forwarded request context and never follows redirects.
func CheckStargate(ctx context.Context, endpoint string, timeout time.Duration) error {
	u, e := url.Parse(endpoint)
	if e != nil {
		return errors.New("invalid dependency endpoint")
	}
	u.Path = "/readyz"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return errors.New("invalid dependency request")
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return errors.New("dependency unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("dependency not ready")
	}
	return nil
}

func openAudit(path, database string) (audit.Storage, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, errors.New("audit directory unavailable")
	}
	if st, e := os.Lstat(path); e == nil {
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("audit file must be a regular owner-only file")
		}
		if db, e := os.Stat(database); e == nil && os.SameFile(st, db) {
			return nil, errors.New("audit file aliases the session database")
		}
	} else if !os.IsNotExist(e) {
		return nil, errors.New("audit file unavailable")
	}
	f, e := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return nil, errors.New("audit file unavailable")
	}
	if e = f.Close(); e != nil {
		return nil, errors.New("audit file unavailable")
	}
	storage, e := audit.NewFileStorage(path)
	if e != nil {
		return nil, errors.New("audit storage unavailable")
	}
	return storage, nil
}

// Keep raw OS/storage errors out of the kit's own worker error log too.
type redactedStorage struct{ audit.Storage }

func (s redactedStorage) Write(ctx context.Context, r *audit.Record) error {
	if e := s.Storage.Write(ctx, r); e != nil {
		return errors.New("audit storage write failed")
	}
	return nil
}

// A loopback peer alone is insufficient for an unkeyed HTTP listener: reject
// non-loopback Host values so a rebinding domain cannot read management data.
func loopbackHost(value string) bool {
	host := value
	if parsed, _, err := net.SplitHostPort(value); err == nil {
		host = parsed
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
