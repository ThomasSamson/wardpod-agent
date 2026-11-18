package scanner

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
)

// TestMatcherRealTrivy : recherche réelle dans le SBOM de composer:2.8
// (testdata), avec trivy dans le PATH et le cache de TEST_TRIVY_CACHE.
func TestMatcherRealTrivy(t *testing.T) {
	cache := os.Getenv("TEST_TRIVY_CACHE")
	path, err := exec.LookPath("trivy")
	if cache == "" || err != nil {
		if os.Getenv("REQUIRE_TRIVY") != "" {
			t.Fatal("REQUIRE_TRIVY défini mais trivy ou TEST_TRIVY_CACHE absent")
		}
		t.Skip("trivy ou TEST_TRIVY_CACHE absent : recherche réelle ignorée")
	}
	cfg := config.Default().Scanner
	cfg.TrivyPath, cfg.CacheDir = path, cache
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	version, err := m.UpdateDB(ctx)
	if err != nil || version == "" {
		t.Fatalf("base : %q %v", version, err)
	}
	doc, err := os.ReadFile("testdata/composer-2.8.cdx.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	osFamily, _, vulns, err := m.Match(ctx, doc, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	if osFamily != "alpine" || len(vulns) == 0 {
		t.Fatalf("composer:2.8 : système %q, %d vulnérabilités", osFamily, len(vulns))
	}
	if _, _, _, err := m.Match(ctx, []byte("pas du gzip"), 64<<20); err == nil {
		t.Fatal("document invalide accepté")
	}
}
