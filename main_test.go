package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ThomasSamson/wardpod-agent/model"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func runCmd(t *testing.T, env []string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, env, strings.NewReader(""), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRunUsage(t *testing.T) {
	if code, _, stderr := runCmd(t, nil); code != 2 || !strings.Contains(stderr, "Sous-commandes") {
		t.Fatalf("sans argument : code %d, %q", code, stderr)
	}
	if code, _, _ := runCmd(t, nil, "inconnue"); code != 2 {
		t.Fatalf("sous-commande inconnue : code %d", code)
	}
	if code, _, _ := runCmd(t, nil, "agent", "-option-inconnue"); code != 2 {
		t.Fatalf("option inconnue : code %d", code)
	}
	if code, out, _ := runCmd(t, nil, "version"); code != 0 || strings.TrimSpace(out) != "dev" {
		t.Fatalf("version : code %d, %q", code, out)
	}
}

func TestRunRejectsPositionalArgs(t *testing.T) {
	// « -b false » se lit comme -b suivi d'un argument : il doit être refusé,
	// pas activer l'option en silence.
	code, out, stderr := runCmd(t, nil, "config", "-agent.allowInsecure", "false")
	if code != 2 || strings.Contains(out, "allowInsecure: true") || !strings.Contains(stderr, "argument inattendu") {
		t.Fatalf("code %d, sortie %q, erreur %q", code, out, stderr)
	}
	if code, _, _ := runCmd(t, nil, "config", "-agent.allowInsecure=false"); code != 0 {
		t.Fatalf("-option=false doit être accepté : code %d", code)
	}
}

func TestRunFlagErrorsInFrench(t *testing.T) {
	_, _, stderr := runCmd(t, nil, "config", "-collect.interval", "dix")
	if !strings.Contains(stderr, "valeur") || strings.Contains(stderr, "invalid value") {
		t.Fatalf("message non traduit : %q", stderr)
	}
	_, _, stderr = runCmd(t, nil, "config", "-inconnue")
	if !strings.Contains(stderr, "option inconnue : -inconnue") {
		t.Fatalf("message non traduit : %q", stderr)
	}
	code, _, stderr := runCmd(t, []string{"WP_COLLECT_CLUSTER=depuis-env"}, "agent", "-h")
	if code != 0 || !strings.Contains(stderr, "Options (valeur par défaut") || strings.Contains(stderr, "depuis-env") {
		t.Fatalf("aide inattendue (code %d) : %s", code, stderr)
	}
}

func TestRunKeepsStdoutClean(t *testing.T) {
	env := []string{"WP_COLECT_CLUSTER=faute-de-frappe"}
	code, out, stderr := runCmd(t, env, "config")
	if code != 0 || strings.Contains(out, `{"time"`) || !strings.Contains(stderr, "WP_COLECT_CLUSTER") {
		t.Fatalf("code %d, sortie %q, erreur %q", code, out, stderr)
	}
	if _, out, _ := runCmd(t, env, "version"); strings.TrimSpace(out) != "dev" {
		t.Fatalf("version : %q", out)
	}
	code, out, stderr = runCmd(t, []string{"WP_AGENT_SERVER_URL=http://serveur.example.org"}, "config", "-check", "agent")
	if code != 1 || strings.Contains(out, "arrêt sur erreur") || !strings.Contains(stderr, "arrêt sur erreur") {
		t.Fatalf("code %d, sortie %q, erreur %q", code, out, stderr)
	}
	// Le niveau de log configuré s'applique aussi à cet avertissement.
	if _, _, stderr := runCmd(t, append(env, "WP_LOG_LEVEL=error"), "config"); strings.Contains(stderr, "WP_COLECT_CLUSTER") {
		t.Fatalf("avertissement émis malgré WP_LOG_LEVEL=error : %q", stderr)
	}
}

func TestRunConfig(t *testing.T) {
	code, out, _ := runCmd(t, []string{"WP_AGENT_TOKEN=jeton-factice", "WP_COLLECT_CLUSTER=prod-1"}, "config", "-collect.environment", "prod")
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	if strings.Contains(out, "jeton-factice") || !strings.Contains(out, "cluster: prod-1") || !strings.Contains(out, "environment: prod") {
		t.Fatalf("sortie inattendue :\n%s", out)
	}
	if code, _, _ := runCmd(t, []string{"WP_AGENT_SERVER_URL=https://serveur.example.org"}, "config"); code != 0 {
		t.Fatalf("sans -check, seules les clés communes sont validées : code %d", code)
	}
	if code, _, _ := runCmd(t, []string{"WP_AGENT_SERVER_URL=https://serveur.example.org", "WP_AGENT_TOKEN=x", "WP_COLLECT_CLUSTER=c1"}, "config", "-check", "agent"); code != 0 {
		t.Fatalf("configuration d'agent valide refusée : code %d", code)
	}
	if code, _, _ := runCmd(t, nil, "config", "-check", "server"); code != 2 {
		t.Fatalf("-check server n'existe pas dans l'agent : code %d", code)
	}
	if code, _, _ := runCmd(t, nil, "config", "-check", "agent"); code != 1 {
		t.Fatalf("agent sans jeton ni cluster accepté : code %d", code)
	}
	if code, _, _ := runCmd(t, nil, "config", "-check", "autre"); code != 2 {
		t.Fatalf("-check inconnu : code %d", code)
	}
	if code, _, _ := runCmd(t, []string{"WP_COLLECT_INTERVAL=abc"}, "config"); code != 1 {
		t.Fatalf("variable illisible : code %d, 1 attendu", code)
	}
}

func TestRunAgentValidation(t *testing.T) {
	code, stdout, _ := runCmd(t, []string{"WP_AGENT_SERVER_URL=http://serveur.example.org", "WP_SCORING_P1=10"}, "agent", "-cluster", "c1")
	if code != 1 || !strings.Contains(stdout, "jeton manquant") || !strings.Contains(stdout, "http://") {
		t.Fatalf("code %d, logs : %s", code, stdout)
	}
	// Une variable du serveur (configuration partagée) n'arrête pas l'agent.
	if !strings.Contains(stdout, "WP_SCORING_P1") || strings.Contains(stdout, "configuration illisible") {
		t.Fatalf("variable du serveur : avertissement attendu, pas d'erreur : %s", stdout)
	}
	// Hors du cluster, sans contexte explicite, l'agent refuse de deviner.
	code, stdout, _ = runCmd(t, []string{"WP_AGENT_SERVER_URL=https://serveur.example.org", "WP_AGENT_TOKEN=x"}, "agent", "-cluster", "c1")
	if code != 1 || !strings.Contains(stdout, "collect.kubeContext") {
		t.Fatalf("code %d, logs : %s", code, stdout)
	}
}

func envtestKubeconfig(t *testing.T) (string, string) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("REQUIRE_ENVTEST") != "" {
			t.Fatal("REQUIRE_ENVTEST défini mais KUBEBUILDER_ASSETS vide")
		}
		t.Skip("KUBEBUILDER_ASSETS non défini : test d'intégration ignoré")
	}
	preserve := true
	env := &envtest.Environment{CRDs: []*apiextv1.CustomResourceDefinition{{
		ObjectMeta: metav1.ObjectMeta{Name: "vulnerabilityreports.aquasecurity.github.io"},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: "aquasecurity.github.io", Scope: apiextv1.NamespaceScoped,
			Names: apiextv1.CustomResourceDefinitionNames{Kind: "VulnerabilityReport", ListKind: "VulnerabilityReportList", Plural: "vulnerabilityreports", Singular: "vulnerabilityreport"},
			Versions: []apiextv1.CustomResourceDefinitionVersion{{Name: "v1alpha1", Served: true, Storage: true,
				Schema: &apiextv1.CustomResourceValidation{OpenAPIV3Schema: &apiextv1.JSONSchemaProps{Type: "object", XPreserveUnknownFields: &preserve}}}},
		},
	}}}
	if _, err := env.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	user, err := env.AddUser(envtest.User{Name: "agent", Groups: []string{"system:masters"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	kc, err := user.KubeConfig()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, kc, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, currentContext(kc)
}

func currentContext(kc []byte) string {
	for line := range strings.SplitSeq(string(kc), "\n") {
		if v, ok := strings.CutPrefix(line, "current-context: "); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func TestRunAgentDump(t *testing.T) {
	kubeconfig, kctx := envtestKubeconfig(t)
	t.Setenv("KUBECONFIG", kubeconfig)
	code, out, stderr := runCmd(t, []string{"WP_COLECT_CLUSTER=faute-de-frappe"}, "agent", "-dump", "-context", kctx, "-cluster", "test", "-collect.environment", "staging")
	if code != 0 {
		t.Fatalf("code %d : %s", code, stderr)
	}
	var snap model.Snapshot
	if err := json.Unmarshal([]byte(out), &snap); err != nil {
		t.Fatalf("la sortie standard doit être le seul snapshot : %v\n%s", err, out)
	}
	if snap.Cluster != "test" || snap.Environment != "staging" || snap.Version != model.SnapshotVersion || snap.Reports == nil {
		t.Fatalf("snapshot inattendu : %+v", snap)
	}
	if !strings.Contains(stderr, "caches synchronisés") {
		t.Fatalf("les logs doivent passer sur la sortie d'erreur : %q", stderr)
	}
}

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func TestRunAgentLifecycle(t *testing.T) {
	kubeconfig, kctx := envtestKubeconfig(t)
	t.Setenv("KUBECONFIG", kubeconfig)

	var mu sync.Mutex
	var received []model.Snapshot
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var s model.Snapshot
		if err := json.NewDecoder(zr).Decode(&s); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, s)
		mu.Unlock()
	}))
	defer srv.Close()

	probes := freePort(t)
	env := []string{"WP_AGENT_SERVER_URL=" + srv.URL, "WP_AGENT_TOKEN=jeton-factice", "WP_AGENT_LISTEN=" + probes, "WP_SHUTDOWN_TIMEOUT=2s"}
	done := make(chan int)
	var stdout safeBuffer
	go func() {
		done <- run([]string{"agent", "-context", kctx, "-cluster", "c1"}, env, strings.NewReader(""), &stdout, io.Discard)
	}()

	waitFor(t, func() bool {
		resp, err := http.Get("http://" + probes + "/readyz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(received) > 0 })
	if resp, err := http.Get("http://" + probes + "/healthz"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz : %v", err)
	}

	// Arrêt propre sur SIGTERM.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("arrêt avec le code %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("l'agent ne s'arrête pas sur SIGTERM")
	}
	logs := stdout.String()
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log non JSON sur la sortie standard : %q", line)
		}
	}
	if !strings.Contains(logs, "arrêt de l'agent") || strings.Contains(logs, "jeton-factice") {
		t.Fatalf("logs inattendus :\n%s", logs)
	}
	if _, err := net.Dial("tcp", probes); err == nil {
		t.Fatal("le port des sondes doit être libéré à l'arrêt")
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for !cond() {
		select {
		case <-ctx.Done():
			t.Fatal("condition non atteinte")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func TestDefaultHandlerOrder(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	defer slog.SetDefault(prev)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	slog.New(defaultHandler{}).With("a", 1).WithGroup("g").With("b", 2).Info("m", "c", 3)
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	g, _ := got["g"].(map[string]any)
	if got["a"] != float64(1) || g == nil || g["b"] != float64(2) || g["c"] != float64(3) {
		t.Fatalf("attributs mal ordonnés : %s", buf.String())
	}
}

func TestParseInterspersed(t *testing.T) {
	for _, tt := range []struct {
		args []string
		pos  []string
		name string
	}{
		{[]string{"create", "c1", "-name", "a"}, []string{"create", "c1"}, "a"},
		{[]string{"-name", "a", "create", "c1"}, []string{"create", "c1"}, "a"},
		{[]string{"create", "-name", "a", "c1"}, []string{"create", "c1"}, "a"},
		{[]string{"create", "--", "-name", "a"}, []string{"create", "-name", "a"}, ""},
		// « -- » valeur de -name : ce n'est pas la fin des options.
		{[]string{"create", "-name", "--", "c1"}, []string{"create", "c1"}, "--"},
		{[]string{"--", "-x"}, []string{"-x"}, ""},
		{nil, nil, ""},
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		name := fs.String("name", "", "")
		pos, err := parseInterspersed(fs, tt.args)
		if err != nil || !slices.Equal(pos, tt.pos) || *name != tt.name {
			t.Errorf("%v : %v %q %v", tt.args, pos, *name, err)
		}
	}
}

func TestRunProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		http.Error(w, "base de données injoignable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if code, out, _ := runCmd(t, nil, "probe", "-url", srv.URL+"/readyz"); code != 0 || !strings.Contains(out, "200") {
		t.Fatalf("sonde prête : %d %q", code, out)
	}
	if code, _, stderr := runCmd(t, nil, "probe", "-url", srv.URL+"/autre"); code == 0 || !strings.Contains(stderr, "503") {
		t.Fatalf("sonde en échec : %d %q", code, stderr)
	}
	if code, _, _ := runCmd(t, nil, "probe", "-url", "ftp://x"); code != 2 {
		t.Fatalf("URL invalide : code %d", code)
	}
}
