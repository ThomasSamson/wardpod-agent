package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// chartDir : le chart de l'agent, dans ce dépôt.
var chartDir = filepath.Join("charts", "wardpod-agent")

// TestChartConfigAcceptedByBinary rend la ConfigMap du chart pour chaque jeu
// de values de ci/ et la soumet à `wardpod config -check` : une
// variable mal nommée par le chart, ou une configuration refusée par le
// binaire, fait échouer le test. Ignoré si helm est absent, sauf avec
// REQUIRE_HELM.
func TestChartConfigAcceptedByBinary(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv("REQUIRE_HELM") != "" {
			t.Fatal("REQUIRE_HELM défini mais helm introuvable")
		}
		t.Skip("helm introuvable")
	}
	type values struct{ chart, file string }
	var cases []values
	for _, chart := range []string{chartDir} {
		files, _ := filepath.Glob(filepath.Join(chart, "ci", "*-values.yaml"))
		if len(files) == 0 {
			t.Fatalf("aucun jeu de values dans %s/ci", chart)
		}
		for _, f := range files {
			cases = append(cases, values{chart, f})
		}
	}
	for _, c := range cases {
		f := c.file
		t.Run(filepath.Base(c.chart)+"/"+filepath.Base(f), func(t *testing.T) {
			out, err := exec.Command("helm", "template", "ti", c.chart, "-f", f).Output()
			if err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					t.Fatalf("helm template : %s", ee.Stderr)
				}
				t.Fatal(err)
			}
			// Chaque Deployment est validé avec son propre environnement :
			// la ConfigMap, ses variables, et une valeur factice pour chaque
			// secret qu'il reçoit d'un Secret. Un pod privé d'un secret
			// dont il a besoin est ainsi repéré.
			fakes := map[string]string{
				"WP_AGENT_TOKEN":           "tik_factice",
				"WP_SCANNER_REGISTRY_AUTH": `{"auths":{}}`,
			}
			type envVar struct {
				Name      string         `yaml:"name"`
				Value     string         `yaml:"value"`
				ValueFrom map[string]any `yaml:"valueFrom"`
			}
			type deployment struct {
				name string
				args []string
				env  []envVar
			}
			var configMap []string
			var deployments []deployment
			dec := yaml.NewDecoder(bytes.NewReader(out))
			for {
				var doc struct {
					Kind     string                `yaml:"kind"`
					Metadata struct{ Name string } `yaml:"metadata"`
					Data     map[string]string     `yaml:"data"`
					Spec     struct {
						Template struct {
							Spec struct {
								Containers []struct {
									Args []string `yaml:"args"`
									Env  []envVar `yaml:"env"`
								} `yaml:"containers"`
							} `yaml:"spec"`
						} `yaml:"template"`
					} `yaml:"spec"`
				}
				if err := dec.Decode(&doc); err != nil {
					break
				}
				switch doc.Kind {
				case "ConfigMap":
					for k, v := range doc.Data {
						configMap = append(configMap, k+"="+v)
					}
				case "Deployment":
					if c := doc.Spec.Template.Spec.Containers; len(c) > 0 && len(c[0].Args) > 0 {
						deployments = append(deployments, deployment{doc.Metadata.Name, c[0].Args, c[0].Env})
					}
				}
			}
			if len(deployments) == 0 {
				t.Fatal("aucun Deployment rendu")
			}
			for _, d := range deployments {
				env := append([]string{}, configMap...)
				for _, e := range d.env {
					switch {
					case e.ValueFrom == nil:
						env = append(env, e.Name+"="+e.Value)
					case fakes[e.Name] != "":
						env = append(env, e.Name+"="+fakes[e.Name])
					default:
						t.Fatalf("%s : variable %s lue d'un Secret sans valeur factice dans le test", d.name, e.Name)
					}
				}
				mode := d.args[0]
				if mode != "agent" {
					t.Fatalf("%s : mode du conteneur inattendu %q", d.name, mode)
				}
				code, _, stderr := runCmd(t, env, "config", "-check", mode)
				if code != 0 {
					t.Fatalf("%s : configuration refusée par le binaire (code %d) :\n%s", d.name, code, stderr)
				}
				if strings.Contains(stderr, "inconnue") {
					t.Fatalf("%s : variable inconnue du binaire :\n%s", d.name, stderr)
				}
			}
		})
	}
}

// TestChartSchemaCoversValues vérifie que values.schema.json décrit chaque
// clé de values.yaml : une value ajoutée sans son schéma serait refusée
// (additionalProperties) au premier usage.
func TestChartSchemaCoversValues(t *testing.T) {
	dir := chartDir
	raw, err := os.ReadFile(filepath.Join(dir, "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, "values.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	var walk func(path string, v map[string]any, s map[string]any)
	walk = func(path string, v map[string]any, s map[string]any) {
		props, _ := s["properties"].(map[string]any)
		if props == nil {
			if s["additionalProperties"] == false {
				t.Errorf("%s : objet fermé sans propriétés", path)
			}
			return // objet libre (annotations, ressources…)
		}
		for k, val := range v {
			sub, ok := props[k].(map[string]any)
			if !ok {
				t.Errorf("%s%s : absent de values.schema.json", path, k)
				continue
			}
			if m, ok := val.(map[string]any); ok {
				walk(path+k+".", m, sub)
			}
		}
		for k := range props {
			if _, ok := v[k]; !ok && !(path == "" && k == "global") {
				t.Errorf("%s%s : dans le schéma mais pas dans values.yaml", path, k)
			}
		}
	}
	walk("", values, schema)
}
