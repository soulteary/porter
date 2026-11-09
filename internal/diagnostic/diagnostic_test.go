package diagnostic

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/store"
)

func configuration(t *testing.T) config.Config {
	t.Helper()
	c := config.Config{PublicURL: "https://porter.test", LandingURL: "https://porter.test/app", Database: filepath.Join(t.TempDir(), "SECRET-porter.db"), ProxyKey: strings.Repeat("SECRET", 8), Providers: map[string]config.Provider{"github": {ClientID: "app", ClientSecret: "SECRET"}}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	return c
}
func TestOfflineChecksDoNotOpenOrModifyDatabase(t *testing.T) {
	c := configuration(t)
	var network atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { network.Add(1) }))
	defer server.Close()
	c.StargateURL = server.URL + "/_auth"
	c.StargateSecret = strings.Repeat("SECRET", 8)
	db, e := store.Open(c.Database)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	before, e := os.ReadFile(c.Database)
	if e != nil {
		t.Fatal(e)
	}
	r := Run(context.Background(), c, false)
	if !r.OK || network.Load() != 0 {
		t.Fatal("offline diagnostic contacted dependency", r)
	}
	after, _ := os.ReadFile(c.Database)
	if !bytes.Equal(before, after) {
		t.Fatal("diagnostic changed database")
	}
	if _, e = os.Stat(c.Operations.AuditFile); !os.IsNotExist(e) {
		t.Fatal("diagnostic created audit file")
	}
	var out bytes.Buffer
	if e = Print(&out, r, true); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "SECRET") {
		t.Fatal("diagnostic leaked configuration")
	}
}
func TestNetworkProbeIsExplicitAndRedacted(t *testing.T) {
	c := configuration(t)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/readyz" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Stargate-Header-Auth") != "" {
			t.Error("diagnostic sent authentication data")
		}
		http.Error(w, "SECRET", 503)
	}))
	defer server.Close()
	c.StargateURL = server.URL + "/_auth"
	c.StargateSecret = strings.Repeat("SECRET", 8)
	r := Run(context.Background(), c, true)
	if r.OK || hits.Load() != 1 {
		t.Fatal(r, hits.Load())
	}
	var out bytes.Buffer
	_ = Print(&out, r, false)
	if strings.Contains(out.String(), "SECRET") || !strings.Contains(out.String(), "stargate_readiness") {
		t.Fatal(out.String())
	}
}

func TestDoctorRejectsAuditDatabaseAlias(t *testing.T) {
	c := configuration(t)
	if e := os.WriteFile(c.Database, []byte("database"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(c.Database, c.Operations.AuditFile); e != nil {
		t.Fatal(e)
	}
	r := Run(context.Background(), c, false)
	if r.OK {
		t.Fatal("aliased audit destination passed")
	}
}
