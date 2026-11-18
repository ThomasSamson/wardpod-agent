package scanner

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
)

// TestIntegrationRealTrivy analyse une vraie image publique avec le vrai
// trivy (réseau requis). Ignoré sans TEST_TRIVY_CACHE (répertoire de cache
// partagé entre essais, pour ne pas retélécharger la base).
func TestIntegrationRealTrivy(t *testing.T) {
	cache := os.Getenv("TEST_TRIVY_CACHE")
	if cache == "" {
		if os.Getenv("REQUIRE_TRIVY") != "" {
			t.Fatal("REQUIRE_TRIVY défini mais TEST_TRIVY_CACHE vide")
		}
		t.Skip("TEST_TRIVY_CACHE non défini : analyse réelle ignorée")
	}
	path, err := exec.LookPath("trivy")
	if err != nil {
		t.Fatal("trivy introuvable")
	}
	cfg := config.Default().Scanner
	cfg.TrivyPath, cfg.CacheDir = path, cache
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := s.Check(ctx); err != nil {
		t.Fatal(err)
	}
	go s.Run(ctx)
	// alpine 3.19.1, par digest : contenu figé, vulnérabilités connues.
	s.Want([]Image{{Digest: dig, Ref: "docker.io/library/alpine@" + dig}})
	for {
		if r, errMsg, ok := s.Result(dig); ok {
			if r.OSFamily != "alpine" || len(r.Vulns) == 0 {
				t.Fatalf("résultat inattendu : %+v", r)
			}
			t.Logf("%d vulnérabilités, base du %s", len(r.Vulns), r.DBUpdatedAt.Format(time.DateOnly))
			return
		} else if errMsg != "" {
			t.Fatal(errMsg)
		}
		select {
		case <-ctx.Done():
			t.Fatal("analyse non terminée")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// TestIntegrationRealRuntime : le PHP compilé dans l'image composer,
// invisible de trivy, apparaît dans le SBOM par PHP_VERSION.
func TestIntegrationRealRuntime(t *testing.T) {
	cache := os.Getenv("TEST_TRIVY_CACHE")
	path, err := exec.LookPath("trivy")
	if cache == "" || err != nil {
		if os.Getenv("REQUIRE_TRIVY") != "" {
			t.Fatal("REQUIRE_TRIVY défini mais trivy ou TEST_TRIVY_CACHE absent")
		}
		t.Skip("trivy ou TEST_TRIVY_CACHE absent")
	}
	cfg := config.Default().Scanner
	tr := &trivy{path: path, cacheDir: cache}
	out := t.TempDir() + "/composer.cdx.json"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := tr.sbom(ctx, "docker.io/library/composer:2.8", out, "", cfg.RuntimeEnv); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"purl":"pkg:generic/php@`) || !strings.Contains(string(data), `"bomFormat":"CycloneDX"`) {
		t.Fatalf("SBOM sans le runtime PHP :\n%.2000s", data)
	}
}
