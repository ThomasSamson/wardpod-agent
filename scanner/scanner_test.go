package scanner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
)

const dig = "sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b"

func TestPullRef(t *testing.T) {
	for in, want := range map[string]string{
		"docker-pullable://nginx@" + dig:              "nginx@" + dig,
		"docker.io/library/alpine@" + dig:             "docker.io/library/alpine@" + dig,
		"registry.example.org:5000/equipe/app@" + dig: "registry.example.org:5000/equipe/app@" + dig,
		"localhost/app@" + dig:                        "localhost/app@" + dig,
	} {
		ref, d, err := PullRef(in)
		if err != nil || ref != want || d != dig {
			t.Errorf("%s : %q %q %v", in, ref, d, err)
		}
	}
	for _, bad := range []string{dig, "", "nginx:1.25", "nginx@sha256:court", "@" + dig,
		"--server=http://evil.example@" + dig, "--input=/etc/hostname@" + dig, "nginx@sha256:" + strings.Repeat("Z", 64),
		"équipe/app@" + dig, "Nginx@" + dig, "a b@" + dig} {
		if _, _, err := PullRef(bad); err == nil {
			t.Errorf("%q accepté", bad)
		}
	}
}

func TestSplitImage(t *testing.T) {
	for in, want := range map[string][3]string{
		"nginx":                                   {"index.docker.io", "library/nginx", "latest"},
		"nginx:1.25":                              {"index.docker.io", "library/nginx", "1.25"},
		"docker.io/bitnami/redis:7":               {"index.docker.io", "bitnami/redis", "7"},
		"ghcr.io/org/app:v1@" + dig:               {"ghcr.io", "org/app", "v1"},
		"registry.example.org:5000/team/app":      {"registry.example.org:5000", "team/app", "latest"},
		"localhost/app:dev":                       {"localhost", "app", "dev"},
		"quay.io/prometheus/node-exporter@" + dig: {"quay.io", "prometheus/node-exporter", ""},
	} {
		r, repo, tag := SplitImage(in)
		if [3]string{r, repo, tag} != want {
			t.Errorf("%s : %q %q %q", in, r, repo, tag)
		}
	}
}

// fakeTrivy écrit un faux binaire trivy qui imite les sous-commandes
// utilisées : les tests unitaires ne dépendent ni du réseau ni de la base.
func fakeTrivy(t *testing.T, failSBOM *atomic.Bool) (string, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	fail := filepath.Join(dir, "fail")
	script := `#!/bin/sh
echo "$@" >> ` + calls + `
case "$1" in
version) echo '{"Version":"0.0-test","VulnerabilityDB":{"UpdatedAt":"2026-10-01T00:00:00Z"}}' ;;
image)
  case "$*" in *--download-db-only*) exit 0 ;; esac
  if [ -f ` + fail + ` ]; then echo "registre injoignable" >&2; exit 1; fi
  for a in "$@"; do if [ "$prev" = "--output" ]; then echo '{"Metadata":{"ImageConfig":{"config":{"Env":["PATH=/usr/bin","PHP_VERSION=8.4.14"]}}}}' > "$a"; fi; prev="$a"; done ;;
convert)
  for a in "$@"; do if [ "$prev" = "--output" ]; then echo '{"bomFormat":"CycloneDX","components":[{"type":"library","purl":"pkg:apk/alpine/musl@1.2"}]}' > "$a"; fi; prev="$a"; done ;;
sbom) echo '{"Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"}},"Results":[{"Target":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"busybox","InstalledVersion":"1","FixedVersion":"2","Severity":"high","SeveritySource":"nvd","CVSS":{"nvd":{"V3Score":7.5}},"PrimaryURL":"https://x/1"}]}]}' ;;
esac
`
	p := filepath.Join(dir, "trivy")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if failSBOM != nil && failSBOM.Load() {
		os.WriteFile(fail, nil, 0o600)
	}
	var n atomic.Int32
	return p, &n
}

func testCfg(t *testing.T, trivyPath string) config.Scanner {
	c := config.Default().Scanner
	c.TrivyPath = trivyPath
	c.CacheDir = t.TempDir()
	c.RetryInterval = 50 * time.Millisecond
	c.MaxRetryInterval = 200 * time.Millisecond
	c.Timeout = 10 * time.Second
	return c
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition non atteinte")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestScannerLifecycle(t *testing.T) {
	trivyPath, _ := fakeTrivy(t, nil)
	var notified atomic.Int32
	s, err := New(testCfg(t, trivyPath), func() { notified.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Check(ctx); err != nil {
		t.Fatal(err)
	}
	go s.Run(ctx)
	s.Want([]Image{{Digest: dig, Ref: "alpine@" + dig}})
	waitFor(t, func() bool { _, _, ok := s.Result(dig); return ok })
	res, _, _ := s.Result(dig)
	if len(res.Vulns) != 1 || res.Vulns[0].Severity != "HIGH" || res.Vulns[0].Score != 7.5 || res.OSFamily != "alpine" || res.Vulns[0].Target != "alpine" {
		t.Fatalf("résultat : %+v", res)
	}
	if notified.Load() == 0 {
		t.Fatal("la collecte n'a pas été prévenue")
	}
	if _, err := os.Stat(s.sbomPath(dig)); err != nil {
		t.Fatal("SBOM non gardé en cache")
	}
	// Une image qui ne sert plus est oubliée.
	s.Want(nil)
	if _, _, ok := s.Result(dig); ok {
		t.Fatal("image oubliée encore présente")
	}
	// Elle revient : le SBOM en cache est réutilisé, sans nouveau tirage.
	s.Want([]Image{{Digest: dig, Ref: "alpine@" + dig}})
	waitFor(t, func() bool { _, _, ok := s.Result(dig); return ok })
}

func TestScannerRetriesAndExcludes(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	trivyPath, _ := fakeTrivy(t, &fail)
	cfg := testCfg(t, trivyPath)
	cfg.Exclude = []string{"registry.internal/*"}
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Want([]Image{{Digest: dig, Ref: "alpine@" + dig}, {Digest: "sha256:" + strings.Repeat("a", 64), Ref: "registry.internal/app@sha256:" + strings.Repeat("a", 64)}})
	waitFor(t, func() bool { _, e, _ := s.Result(dig); return strings.Contains(e, "registre injoignable") })
	if st := s.Status(); st.Failed != 1 || st.Pending+st.Scanned != 0 {
		t.Fatalf("état : %+v (l'image exclue ne doit pas compter)", st)
	}
	// La panne cesse : nouvel essai après le délai.
	os.Remove(filepath.Join(filepath.Dir(trivyPath), "fail"))
	waitFor(t, func() bool { _, _, ok := s.Result(dig); return ok })
	if !s.Excluded("registry.internal/app@sha256:x") || s.Excluded("alpine@sha256:x") {
		t.Fatal("exclusions")
	}
}

func TestScannerEnvIsolation(t *testing.T) {
	t.Setenv("WP_AGENT_TOKEN", "tik_secret")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	cfg := testCfg(t, "trivy")
	cfg.RegistryAuth = `{"auths":{"registry.example.org":{"auth":"dXNlcjpwYXNz"}}}`
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := strings.Join(s.t.env(), "\n")
	if strings.Contains(env, "tik_secret") || !strings.Contains(env, "HTTPS_PROXY=http://proxy.example:3128") || !strings.Contains(env, "DOCKER_CONFIG=") {
		t.Fatalf("environnement de trivy : %s", env)
	}
	st, err := os.Stat(filepath.Join(s.t.dockerDir, "config.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("identifiants : %v %v", st, err)
	}
	if strings.HasPrefix(s.t.dockerDir, cfg.CacheDir) {
		t.Fatal("identifiants écrits dans le cache, qui peut être persistant")
	}
	os.RemoveAll(s.t.dockerDir)
	cfg.RegistryAuth = "pas du json"
	if _, err := New(cfg, nil); err == nil {
		t.Fatal("identifiants invalides acceptés")
	}
}

func TestValidateScanner(t *testing.T) {
	ok := config.Default().Scanner
	for _, size := range []string{"", "500MB", "2GB", "2GiB", "2G", "1.5gb", "100"} {
		c := ok
		c.MaxImageSize = size
		if err := Validate(c); err != nil {
			t.Errorf("%q refusé : %v", size, err)
		}
	}
	for name, mutate := range map[string]func(*config.Scanner){
		"taille 2Gi":        func(c *config.Scanner) { c.MaxImageSize = "2Gi" },
		"taille en lettres": func(c *config.Scanner) { c.MaxImageSize = "deux" },
		"identifiants":      func(c *config.Scanner) { c.RegistryAuth = "pas du json" },
		"rétention nulle":   func(c *config.Scanner) { c.SBOMRetention = 0 },
		"concurrence nulle": func(c *config.Scanner) { c.Concurrency = 0 },
		"motif d'exclusion": func(c *config.Scanner) { c.Exclude = []string{"["} },
	} {
		c := ok
		mutate(&c)
		if Validate(c) == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

// Les analyses tournent vraiment en parallèle : un signal ne réveille qu'un
// worker, qui réveille le suivant s'il reste du travail.
func TestScannerConcurrency(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
case "$1" in
version) echo '{"Version":"0.0-test","VulnerabilityDB":{"UpdatedAt":"2026-10-01T00:00:00Z"}}' ;;
image)
  case "$*" in *--download-db-only*) exit 0 ;; esac
  sleep 1
  for a in "$@"; do if [ "$prev" = "--output" ]; then echo '{}' > "$a"; fi; prev="$a"; done ;;
convert)
  for a in "$@"; do if [ "$prev" = "--output" ]; then echo '{"bomFormat":"CycloneDX"}' > "$a"; fi; prev="$a"; done ;;
sbom) echo '{"Results":[]}' ;;
esac
`
	p := filepath.Join(dir, "trivy")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := testCfg(t, p)
	cfg.Concurrency = 4
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	var imgs []Image
	for i := range 8 {
		d := "sha256:" + strings.Repeat(string(rune('a'+i)), 64)
		imgs = append(imgs, Image{Digest: d, Ref: "alpine@" + d})
	}
	start := time.Now()
	s.Want(imgs)
	waitFor(t, func() bool { return s.Status().Scanned == 8 })
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("8 analyses d'une seconde avec 4 workers : %s", d)
	}
}

// La cible des paquets du système ne garde pas le chemin local du SBOM.
func TestMatchTarget(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "sbom", "sha256_x.cdx.json")
	script := `#!/bin/sh
echo '{"Results":[{"Target":"` + sbom + ` (alpine 3.19.1)","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"musl","InstalledVersion":"1","Severity":"LOW"}]},{"Target":"usr/lib/node_modules/npm/package.json","Vulnerabilities":[{"VulnerabilityID":"CVE-2","PkgName":"tar","InstalledVersion":"1","Severity":"LOW"}]}]}'
`
	p := filepath.Join(dir, "trivy")
	os.WriteFile(p, []byte(script), 0o755)
	tr := &trivy{path: p, cacheDir: dir}
	_, _, vulns, err := tr.match(context.Background(), sbom)
	if err != nil {
		t.Fatal(err)
	}
	if vulns[0].Target != "alpine 3.19.1" || vulns[1].Target != "usr/lib/node_modules/npm/package.json" {
		t.Fatalf("cibles : %q, %q", vulns[0].Target, vulns[1].Target)
	}
}

// Recherche par le serveur : le scanner fait le SBOM, sans base ni
// recherche de vulnérabilités.
func TestScannerServerMatch(t *testing.T) {
	trivyPath, _ := fakeTrivy(t, nil)
	cfg := testCfg(t, trivyPath)
	cfg.ServerMatch = true
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Want([]Image{{Digest: dig, Ref: "alpine@" + dig}})
	waitFor(t, func() bool { _, _, ok := s.Result(dig); return ok })
	if res, _, _ := s.Result(dig); len(res.Vulns) != 0 {
		t.Fatalf("vulnérabilités cherchées par l'agent : %+v", res)
	}
	if data, err := s.SBOM(dig); err != nil || len(data) == 0 {
		t.Fatalf("SBOM : %v", err)
	}
	calls, _ := os.ReadFile(filepath.Join(filepath.Dir(trivyPath), "calls"))
	if strings.Contains(string(calls), "--download-db-only") || strings.Contains(string(calls), "sbom ") {
		t.Fatalf("base ou recherche sollicitées :\n%s", calls)
	}
}

// Le cache des SBOM est compressé ; un SBOM non compressé d'une version
// précédente est repris et compressé, sans nouvelle analyse de l'image.
func TestSBOMCacheCompressed(t *testing.T) {
	trivyPath, _ := fakeTrivy(t, nil)
	cfg := testCfg(t, trivyPath)
	cfg.ServerMatch = true
	const old = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	os.MkdirAll(filepath.Join(cfg.CacheDir, "sbom"), 0o700)
	legacy := filepath.Join(cfg.CacheDir, "sbom", "sha256_1111111111111111111111111111111111111111111111111111111111111111.cdx.json")
	os.WriteFile(legacy, []byte(`{"bomFormat":"CycloneDX","ancien":true}`), 0o600)
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Want([]Image{{Digest: dig, Ref: "alpine@" + dig}, {Digest: old, Ref: "alpine@" + old}})
	waitFor(t, func() bool { return s.Status().Scanned == 2 })
	for _, d := range []string{dig, old} {
		raw, err := os.ReadFile(s.sbomPath(d))
		if err != nil || len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
			t.Fatalf("%s : cache non compressé (%v)", d, err)
		}
		if doc, err := s.SBOMCompressed(d, 1<<20); err != nil || !bytes.Equal(doc, raw) {
			t.Fatalf("%s : document complet %v", d, err)
		}
	}
	if data, err := s.SBOM(old); err != nil || !strings.Contains(string(data), "ancien") {
		t.Fatalf("SBOM repris : %q %v", data, err)
	}
	if _, err := os.Stat(legacy); err == nil {
		t.Fatal("SBOM non compressé laissé en cache")
	}
	calls, _ := os.ReadFile(filepath.Join(filepath.Dir(trivyPath), "calls"))
	if strings.Count(string(calls), "image ") != 1 {
		t.Fatalf("une seule image à analyser, appels :\n%s", calls)
	}
}

// Le runtime compilé dans l'image (PHP_VERSION) s'ajoute au SBOM.
func TestSBOMRuntimes(t *testing.T) {
	trivyPath, _ := fakeTrivy(t, nil)
	cfg := testCfg(t, trivyPath)
	cfg.ServerMatch = true
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Want([]Image{{Digest: dig, Ref: "php@" + dig}})
	waitFor(t, func() bool { _, _, ok := s.Result(dig); return ok })
	data, err := s.SBOM(dig)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"purl":"pkg:generic/php@8.4.14"`, `"value":"runtime"`, `"purl":"pkg:apk/alpine/musl@1.2"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("SBOM sans %s :\n%s", want, data)
		}
	}
	if strings.Contains(string(data), "PATH") {
		t.Error("variable hors runtimeEnv reprise")
	}
	entries, _ := os.ReadDir(filepath.Join(cfg.CacheDir, "sbom"))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			t.Errorf("fichier intermédiaire laissé en cache : %s", e.Name())
		}
	}
}
