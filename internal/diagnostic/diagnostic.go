// Package diagnostic runs deployment checks with bounded network probes, without opening the database
// or issuing authentication requests. Probe internals are redacted before output.
package diagnostic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/operations"
	preflight "github.com/soulteary/preflight-kit"
)

type Check struct {
	Name    string          `json:"name"`
	Level   preflight.Level `json:"level"`
	Message string          `json:"message"`
	Hint    string          `json:"hint,omitempty"`
}
type Report struct {
	OK      bool    `json:"ok"`
	Network bool    `json:"network"`
	Checks  []Check `json:"checks"`
}

func Run(ctx context.Context, c config.Config, network bool) Report {
	checks := []preflight.Check{
		preflight.Named("database_directory", func(context.Context) preflight.Result {
			return preflight.DirWritable("database_directory", filepath.Dir(c.Database))
		}),
		preflight.Named("audit_directory", func(context.Context) preflight.Result {
			return preflight.DirWritable("audit_directory", filepath.Dir(c.Operations.AuditFile))
		}),
		preflight.Named("database_file", func(context.Context) preflight.Result { return privateFile("database_file", c.Database) }),
		preflight.Named("audit_file", func(context.Context) preflight.Result { return privateFile("audit_file", c.Operations.AuditFile) }),
		preflight.Named("audit_destination", func(context.Context) preflight.Result {
			database, de := os.Stat(c.Database)
			journal, ae := os.Stat(c.Operations.AuditFile)
			if de == nil && ae == nil && os.SameFile(database, journal) {
				return preflight.Fail("audit_destination", "audit aliases database", "")
			}
			return preflight.OK("audit_destination", "separate audit destination")
		}),
	}
	if network && c.StargateURL != "" {
		checks = append(checks, preflight.Named("stargate_readiness", func(ctx context.Context) preflight.Result {
			timeout := time.Duration(c.Operations.ProbeTimeoutSeconds) * time.Second
			bounded, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			if e := operations.CheckStargate(bounded, c.StargateURL, timeout); e != nil {
				return preflight.Fail("stargate_readiness", "dependency not ready", "check Stargate readiness and TLS configuration")
			}
			return preflight.OK("stargate_readiness", "dependency ready")
		}))
	}
	results := preflight.Run(ctx, checks...)
	report := Report{OK: results.OK(), Network: network, Checks: []Check{{Name: "configuration", Level: preflight.LevelOK, Message: "configuration valid"}}}
	for _, r := range results {
		message, hint := "check passed", ""
		if r.Level == preflight.LevelWarn {
			message = "file is not created yet"
			hint = "the service creates it on first start"
		}
		if r.Failed() {
			message = "check failed"
			hint = "check the configured path, owner permissions and mount access"
			if r.Name == "stargate_readiness" {
				hint = "check Stargate readiness, network access and TLS configuration"
			}
		}
		report.Checks = append(report.Checks, Check{Name: r.Name, Level: r.Level, Message: message, Hint: hint})
	}
	if c.StargateURL == "" {
		report.Checks = append(report.Checks, Check{Name: "authorization_mode", Level: preflight.LevelWarn, Message: "identity-only mode", Hint: "configure Stargate before using /auth"})
	}
	return report
}
func privateFile(name, path string) preflight.Result {
	st, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return preflight.Warn(name, "not created", "")
	}
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return preflight.Fail(name, "invalid private file", "")
	}
	return preflight.OK(name, "private file")
}
func Print(w io.Writer, r Report, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(r)
	}
	for _, c := range r.Checks {
		if _, e := io.WriteString(w, "["+string(c.Level)+"] "+c.Name+": "+c.Message); e != nil {
			return e
		}
		if c.Hint != "" {
			if _, e := io.WriteString(w, "; "+c.Hint); e != nil {
				return e
			}
		}
		if _, e := io.WriteString(w, "\n"); e != nil {
			return e
		}
	}
	return nil
}

// ConfigurationProblem deliberately excludes parser field names and OS paths,
// which can contain secret-bearing user input.
func ConfigurationProblem(err error) string {
	var validation *config.ValidationError
	if errors.As(err, &validation) {
		return "configuration invalid: " + validation.Error()
	}
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		return fmt.Sprintf("invalid JSON at byte %d", syntax.Offset)
	}
	var path *os.PathError
	if errors.As(err, &path) {
		return "configuration file unavailable; check file access"
	}
	return "invalid JSON types or unsupported configuration fields"
}
