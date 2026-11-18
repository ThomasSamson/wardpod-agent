package config

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestDefaultIsValid(t *testing.T) {
	c := Default()
	if err := errors.Join(c.ValidateCommon()); err != nil {
		t.Fatal(err)
	}
}

// TestExampleMatchesDefaults impose que config.example.yaml documente chaque
// clé avec sa valeur par défaut.
func TestExampleMatchesDefaults(t *testing.T) {
	data, err := os.ReadFile("../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var fromExample Config
	if err := ApplyYAML(&fromExample, data); err != nil {
		t.Fatal(err)
	}
	def := Default()
	if !reflect.DeepEqual(fromExample, def) {
		a, _ := fromExample.Redacted()
		b, _ := def.Redacted()
		t.Fatalf("l'exemple diffère des défauts.\nexemple :\n%s\ndéfauts :\n%s", a, b)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	for _, f := range def.Fields() {
		if !hasPath(root.Content[0], strings.Split(f.Path, ".")) {
			t.Errorf("clé %s absente de config.example.yaml", f.Path)
		}
	}
}

func hasPath(n *yaml.Node, path []string) bool {
	if len(path) == 0 {
		return true
	}
	if n.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == path[0] {
			return hasPath(n.Content[i+1], path[1:])
		}
	}
	return false
}

// TestEveryKeyHasEnv vérifie que chaque clé a une variable WP_* unique et
// qu'elle s'applique réellement.
func TestEveryKeyHasEnv(t *testing.T) {
	c := Default()
	seen := map[string]string{}
	for _, f := range c.Fields() {
		if !strings.HasPrefix(f.Env, EnvPrefix) {
			t.Errorf("%s : variable %q sans préfixe", f.Path, f.Env)
		}
		if other, dup := seen[f.Env]; dup {
			t.Errorf("variable %s partagée par %s et %s", f.Env, other, f.Path)
		}
		seen[f.Env] = f.Path
		want := f.String()
		fresh := Config{}
		if _, err := ApplyEnv(&fresh, []string{f.Env + "=" + want}); err != nil {
			t.Errorf("%s=%s : %v", f.Env, want, err)
			continue
		}
		for _, g := range fresh.Fields() {
			if g.Path == f.Path && g.String() != want {
				t.Errorf("%s : %q relu %q", f.Env, want, g.String())
			}
		}
	}
}

// TestEnvNames fige les noms des variables : les clients les utilisent
// (manifeste de la console, chart).
func TestEnvNames(t *testing.T) {
	for path, want := range map[string]string{
		"collect.syncTimeout":                     "WP_COLLECT_SYNC_TIMEOUT",
		"collect.internalLoadBalancerAnnotations": "WP_COLLECT_INTERNAL_LOAD_BALANCER_ANNOTATIONS",
		"agent.serverURL":                         "WP_AGENT_SERVER_URL",
		"agent.httpTimeout":                       "WP_AGENT_HTTP_TIMEOUT",
		"agent.allowInsecure":                     "WP_AGENT_ALLOW_INSECURE",
		"scanner.javaDBRepository":                "WP_SCANNER_JAVA_DB_REPOSITORY",
		"scanner.sbomRetention":                   "WP_SCANNER_SBOM_RETENTION",
		"shutdownTimeout":                         "WP_SHUTDOWN_TIMEOUT",
	} {
		if got := envName(strings.Split(path, ".")); got != want {
			t.Errorf("%s : %s, attendu %s", path, got, want)
		}
	}
}

func TestLoadPrecedence(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "c.yaml")
	os.WriteFile(file, []byte("collect:\n  cluster: fichier\n  environment: fichier\n  interval: 1m\nlog:\n  level: debug\n"), 0o600)
	secret := filepath.Join(dir, "token")
	os.WriteFile(secret, []byte("jeton-factice\n"), 0o600)

	c, _, err := Load([]string{
		"WP_CONFIG=" + file,
		"WP_COLLECT_CLUSTER=env",
		"WP_COLLECT_ENVIRONMENT=env",
		"WP_AGENT_TOKEN_FILE=" + secret,
		`WP_SCANNER_RUNTIME_ENV={"PHP_VERSION":"php"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	c.RegisterFlags(fs)
	Alias(fs, "context", "collect.kubeContext")
	if err := fs.Parse([]string{"-collect.cluster", "flag", "-context", "kind-test", "-agent.allowInsecure"}); err != nil {
		t.Fatal(err)
	}
	if c.Collect.KubeContext != "kind-test" || !c.Agent.AllowInsecure {
		t.Fatalf("flags mal appliqués : %+v %+v", c.Collect, c.Agent)
	}
	if c.Collect.Cluster != "flag" || c.Collect.Environment != "env" || c.Collect.Interval != time.Minute || c.Log.Level != "debug" {
		t.Fatalf("ordre d'application non respecté : %+v", c.Collect)
	}
	if c.Agent.Token != "jeton-factice" {
		t.Fatalf("WP_AGENT_TOKEN_FILE non lu : %q", c.Agent.Token)
	}
	if e := c.Scanner.RuntimeEnv; len(e) != 1 || e["PHP_VERSION"] != "php" {
		t.Fatalf("table JSON mal lue : %v", e)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	unknownKey := filepath.Join(dir, "u.yaml")
	os.WriteFile(unknownKey, []byte("collect:\n  clustre: x\n"), 0o600)
	serverKey := filepath.Join(dir, "s.yaml")
	os.WriteFile(serverKey, []byte("server:\n  listen: :8080\n"), 0o600)
	secret := filepath.Join(dir, "s")
	os.WriteFile(secret, []byte("x"), 0o600)
	for name, env := range map[string][]string{
		"clé YAML inconnue":             {"WP_CONFIG=" + unknownKey},
		"section du serveur":            {"WP_CONFIG=" + serverKey},
		"fichier absent":                {"WP_CONFIG=" + filepath.Join(dir, "absent.yaml")},
		"durée invalide":                {"WP_COLLECT_INTERVAL=dix minutes"},
		"JSON invalide":                 {"WP_SCANNER_RUNTIME_ENV={"},
		"secret en double":              {"WP_AGENT_TOKEN=a", "WP_AGENT_TOKEN_FILE=" + secret},
		"fichier de secret introuvable": {"WP_AGENT_TOKEN_FILE=" + filepath.Join(dir, "absent")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Load(env); err == nil {
				t.Fatal("erreur attendue")
			}
		})
	}
}

// Une variable du serveur (configuration partagée) est signalée, pas
// refusée : l'agent démarre.
func TestUnknownEnv(t *testing.T) {
	c := Default()
	unknown, err := ApplyEnv(&c, []string{"WP_COLECT_CLUSTER=x", "WP_AGENT_TOKEN_FILE=/dev/null", "PATH=/bin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 1 || unknown[0] != "WP_COLECT_CLUSTER" {
		t.Fatalf("variables inconnues : %v", unknown)
	}
}

func TestStringList(t *testing.T) {
	var v struct {
		L []string `yaml:"l"`
	}
	f := Field{value: reflect.ValueOf(&v).Elem().Field(0)}
	if err := f.Set("a, b,,c"); err != nil || !reflect.DeepEqual(v.L, []string{"a", "b", "c"}) {
		t.Fatalf("%v %v", v.L, err)
	}
	if err := f.Set(`["x,y"]`); err != nil || !reflect.DeepEqual(v.L, []string{"x,y"}) {
		t.Fatalf("%v %v", v.L, err)
	}
}

func TestRedacted(t *testing.T) {
	c := Default()
	c.Agent.Token = "jeton-tres-secret"
	c.Scanner.RegistryAuth = `{"auths":{"r":{"auth":"identifiants"}}}`
	out, err := c.Redacted()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "jeton-tres-secret") || strings.Contains(s, "identifiants") || !strings.Contains(s, "token: '********'") {
		t.Fatalf("secret non masqué :\n%s", s)
	}
	if !strings.Contains(s, "interval: 10m0s") {
		t.Fatalf("durée mal rendue :\n%s", s)
	}
	var back Config
	if err := ApplyYAML(&back, out); err != nil {
		t.Fatal(err)
	}
	back.Agent.Token, back.Scanner.RegistryAuth = c.Agent.Token, c.Scanner.RegistryAuth
	if !reflect.DeepEqual(back, c) {
		t.Fatal("la sortie de Redacted ne se relit pas à l'identique")
	}
}

func TestYAMLReplacesTables(t *testing.T) {
	c := Default()
	if err := ApplyYAML(&c, []byte("scanner:\n  runtimeEnv:\n    PHP_VERSION: php\n")); err != nil {
		t.Fatal(err)
	}
	if e := c.Scanner.RuntimeEnv; len(e) != 1 {
		t.Fatalf("la table doit être remplacée, pas fusionnée : %v", e)
	}
	if c.Scanner.Concurrency != DefaultScanner().Concurrency {
		t.Fatal("les clés absentes du fichier doivent garder leur valeur")
	}
}

func TestEmptyEnvIsUnset(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "token")
	os.WriteFile(secret, []byte("depuis-fichier"), 0o600)
	c, _, err := Load([]string{"WP_AGENT_ALLOW_INSECURE=", "WP_AGENT_TOKEN=", "WP_AGENT_TOKEN_FILE=" + secret, "WP_COLLECT_INTERVAL="})
	if err != nil {
		t.Fatal(err)
	}
	if c.Agent.AllowInsecure || c.Agent.Token != "depuis-fichier" || c.Collect.Interval != Default().Collect.Interval {
		t.Fatalf("variables vides mal traitées : %+v %+v", c.Agent, c.Collect)
	}
}

func TestCheckURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://example.org":           true,
		"http://localhost:8080":         true,
		"http://127.0.0.1":              true,
		"http://[::1]:8080":             true,
		"http://miroir.interne":         false,
		"https://user:secret@h.example": false,
		"ftp://example.org":             false,
		"example.org":                   false,
	} {
		if err := CheckURL(raw, false); (err == nil) != ok {
			t.Errorf("%s : %v", raw, err)
		}
		if err := CheckURL(raw, false); err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("%s : mot de passe recopié dans l'erreur : %v", raw, err)
		}
	}
	if err := CheckURL("http://miroir.interne", true); err != nil {
		t.Errorf("allowInsecure : %v", err)
	}
}

func TestRedactedURL(t *testing.T) {
	c := Default()
	c.Agent.ServerURL = "https://user:motdepasse@serveur.example.org"
	out, _ := c.Redacted()
	if strings.Contains(string(out), "motdepasse") {
		t.Fatalf("mot de passe d'URL non masqué :\n%s", out)
	}
}

func TestFlagDefaultsAreDefaults(t *testing.T) {
	c, _, err := Load([]string{"WP_COLLECT_CLUSTER=depuis-env", "WP_AGENT_TOKEN=jeton-factice"})
	if err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	c.RegisterFlags(fs)
	if d := fs.Lookup("collect.cluster").DefValue; d != "" {
		t.Fatalf("-h doit afficher le défaut, pas la valeur de l'environnement : %q", d)
	}
	if d := fs.Lookup("agent.token").DefValue; d != "" {
		t.Fatalf("un secret n'a pas de valeur affichée : %q", d)
	}
	if d := fs.Lookup("collect.interval").DefValue; d != "10m0s" {
		t.Fatalf("défaut attendu : %q", d)
	}
}
