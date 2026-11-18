package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ThomasSamson/wardpod-agent/model"
)

// trivy pilote le binaire trivy dans un environnement minimal : aucune
// variable du processus parent n'est transmise, hors proxys, pour qu'aucun
// secret de Wardpod (jeton d'agent, DSN) ne lui parvienne.
type trivy struct {
	path      string
	cacheDir  string
	dockerDir string // DOCKER_CONFIG avec les identifiants de registre, ou vide
	dbRepos   []string
	javaRepos []string
}

// proxyVars sont les variables héritées par trivy, avec celles des préfixes
// cloudPrefixes : proxys, certificats, et identité de charge des registres
// des fournisseurs cloud (ECR, Artifact Registry, ACR). Aucune variable de
// Wardpod (WP_*) ne passe.
var proxyVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"}

var cloudPrefixes = []string{"AWS_", "GOOGLE_", "AZURE_"}

func (t *trivy) env() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.cacheDir,
		"TMPDIR=" + filepath.Join(t.cacheDir, "tmp"),
		"TRIVY_NO_PROGRESS=true",
		"TRIVY_DISABLE_VEX_NOTICE=true",
	}
	for _, k := range proxyVars {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	for _, kv := range os.Environ() {
		for _, p := range cloudPrefixes {
			if strings.HasPrefix(kv, p) {
				env = append(env, kv)
			}
		}
	}
	if t.dockerDir != "" {
		env = append(env, "DOCKER_CONFIG="+t.dockerDir)
	}
	return env
}

// maxStderr borne le message d'erreur conservé ; maxStdout, le rapport lu
// (une image hostile peut produire une sortie démesurée).
const (
	maxStderr = 2048
	maxStdout = 256 << 20
)

// cappedBuffer refuse d'écrire au-delà de sa limite.
type cappedBuffer struct {
	bytes.Buffer
	limit int
}

var errTooLarge = errors.New("sortie de trivy trop volumineuse")

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errTooLarge
	}
	return b.Buffer.Write(p)
}

// run lance une sous-commande de trivy. Les options communes suivent le
// nom de la sous-commande ; une référence ou un chemin passe après « -- »,
// pour ne jamais être lu comme une option.
func (t *trivy) run(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{args[0], "--quiet", "--cache-dir", t.cacheDir}, args[1:]...)
	cmd := exec.CommandContext(ctx, t.path, full...)
	cmd.Env = t.env()
	stdout := &cappedBuffer{limit: maxStdout}
	stderr := &cappedBuffer{limit: 1 << 20}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("trivy %s : délai dépassé ou arrêt", args[0])
		}
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > maxStderr {
			msg = msg[len(msg)-maxStderr:]
		}
		return nil, fmt.Errorf("trivy %s : %w : %s", args[0], err, msg)
	}
	return stdout.Bytes(), nil
}

func (t *trivy) repoFlags() []string {
	var out []string
	if len(t.dbRepos) > 0 {
		out = append(out, "--db-repository", strings.Join(t.dbRepos, ","))
	}
	if len(t.javaRepos) > 0 {
		out = append(out, "--java-db-repository", strings.Join(t.javaRepos, ","))
	}
	return out
}

// version renvoie la version de trivy.
func (t *trivy) version(ctx context.Context) (string, error) {
	out, err := t.run(ctx, "version", "--format", "json")
	if err != nil {
		return "", err
	}
	var v struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return "", fmt.Errorf("version de trivy illisible : %w", err)
	}
	return v.Version, nil
}

// dbUpdatedAt renvoie la date de la base de vulnérabilités en cache (zéro si
// absente).
func (t *trivy) dbUpdatedAt(ctx context.Context) (time.Time, error) {
	out, err := t.run(ctx, "version", "--format", "json")
	if err != nil {
		return time.Time{}, err
	}
	var v struct {
		VulnerabilityDB *struct {
			UpdatedAt time.Time `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return time.Time{}, err
	}
	if v.VulnerabilityDB == nil {
		return time.Time{}, nil
	}
	return v.VulnerabilityDB.UpdatedAt, nil
}

// updateDB télécharge la base de vulnérabilités.
func (t *trivy) updateDB(ctx context.Context) error {
	_, err := t.run(ctx, append([]string{"image", "--download-db-only"}, t.repoFlags()...)...)
	return err
}

// sbom produit le SBOM CycloneDX d'une image, tirée directement du
// registre : ni démon Docker ni accès aux nœuds. Aucune recherche de
// vulnérabilités ici : elle se fait sur le SBOM, qui se réévalue sans
// retélécharger l'image.
//
// trivy produit d'abord son rapport JSON, qui porte aussi la configuration
// de l'image, puis le convertit en CycloneDX : les runtimes compilés dans
// l'image (runtimeEnv) s'ajoutent au SBOM, sans second téléchargement.
func (t *trivy) sbom(ctx context.Context, ref, out, maxSize string, runtimeEnv map[string]string) error {
	report := out + ".report.json"
	defer os.Remove(report)
	// Cache des couches en mémoire : deux analyses simultanées ne se
	// disputent pas le cache disque (verrou de trivy), et il ne grossit
	// pas ; le SBOM produit est déjà gardé.
	args := []string{"image", "--image-src", "remote", "--cache-backend", "memory", "--format", "json", "--list-all-pkgs", "--scanners", "", "--output", report}
	if maxSize != "" {
		args = append(args, "--max-image-size", maxSize)
	}
	args = append(args, t.repoFlags()...)
	if _, err := t.run(ctx, append(args, "--", ref)...); err != nil {
		return err
	}
	if _, err := t.run(ctx, "convert", "--format", "cyclonedx", "--output", out, "--", report); err != nil {
		return err
	}
	return addRuntimes(report, out, runtimeEnv)
}

// addRuntimes ajoute au SBOM out les runtimes que déclare la configuration
// de l'image (rapport JSON de trivy) dans les variables runtimeEnv.
func addRuntimes(report, out string, runtimeEnv map[string]string) error {
	if len(runtimeEnv) == 0 {
		return nil
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		return err
	}
	var r struct {
		Metadata struct {
			ImageConfig struct {
				Config struct {
					Env []string `json:"Env"`
				} `json:"config"`
			} `json:"ImageConfig"`
		} `json:"Metadata"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("rapport de trivy illisible : %w", err)
	}
	var runtimes []map[string]any
	for _, kv := range r.Metadata.ImageConfig.Config.Env {
		k, v, _ := strings.Cut(kv, "=")
		name, ok := runtimeEnv[k]
		v = strings.TrimSpace(v)
		if !ok || v == "" || len(v) > 128 {
			continue
		}
		purl := "pkg:generic/" + url.PathEscape(name) + "@" + url.PathEscape(v)
		runtimes = append(runtimes, map[string]any{
			"bom-ref": "wardpod-runtime-" + name, "type": "library", "name": name, "version": v, "purl": purl,
			"properties": []map[string]string{{"name": "aquasecurity:trivy:PkgType", "value": model.PkgTypeRuntime}, {"name": "wardpod:source", "value": k}},
		})
	}
	if len(runtimes) == 0 {
		return nil
	}
	sort.Slice(runtimes, func(i, j int) bool { return runtimes[i]["name"].(string) < runtimes[j]["name"].(string) })
	doc, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	var bom map[string]any
	if err := json.Unmarshal(doc, &bom); err != nil {
		return fmt.Errorf("SBOM de trivy illisible : %w", err)
	}
	cs, _ := bom["components"].([]any)
	for _, rt := range runtimes {
		cs = append(cs, rt)
	}
	bom["components"] = cs
	doc, err = json.Marshal(bom)
	if err != nil {
		return err
	}
	return os.WriteFile(out, doc, 0o600)
}

// trivyReport reprend les champs utiles du rapport JSON de trivy.
type trivyReport struct {
	Metadata struct {
		OS *struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			SeveritySource   string `json:"SeveritySource"`
			Title            string `json:"Title"`
			PrimaryURL       string `json:"PrimaryURL"`
			PublishedDate    string `json:"PublishedDate"`
			PkgIdentifier    struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			CVSS map[string]struct {
				V3Score float64 `json:"V3Score"`
				V2Score float64 `json:"V2Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// match recherche les vulnérabilités d'un SBOM avec la base en cache.
// trivy nomme la cible des paquets du système d'après le fichier analysé
// (« /…/sbom/sha256_….cdx.json (alpine 3.19.1) ») : seul le système est
// gardé (« alpine 3.19.1 »). L'identité des findings ne dépend ainsi ni de
// l'emplacement du cache ni de la référence sous laquelle l'image a été
// vue en premier (le digest en fait déjà partie).
func (t *trivy) match(ctx context.Context, sbomPath string) (osFamily, osName string, vulns []model.Vulnerability, err error) {
	out, err := t.run(ctx, "sbom", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "--", sbomPath)
	if err != nil {
		return "", "", nil, err
	}
	var r trivyReport
	if err := json.Unmarshal(out, &r); err != nil {
		return "", "", nil, fmt.Errorf("rapport de trivy illisible : %w", err)
	}
	if r.Metadata.OS != nil {
		osFamily, osName = r.Metadata.OS.Family, r.Metadata.OS.Name
	}
	vulns = []model.Vulnerability{}
	for _, res := range r.Results {
		target := res.Target
		if rest, ok := strings.CutPrefix(target, sbomPath); ok {
			target = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(rest), "("), ")")
		}
		for _, v := range res.Vulnerabilities {
			vulns = append(vulns, model.Vulnerability{
				ID: v.VulnerabilityID, Package: v.PkgName, InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion,
				Severity: strings.ToUpper(v.Severity), Score: cvssScore(v.SeveritySource, v.CVSS), Title: v.Title,
				PrimaryLink: v.PrimaryURL, Target: target, PURL: v.PkgIdentifier.PURL, PublishedDate: v.PublishedDate,
			})
		}
	}
	return osFamily, osName, vulns, nil
}

// cvssScore choisit le score CVSS v3 de la source de la sévérité, sinon
// celui du NVD, sinon le plus élevé : comme le Trivy Operator.
func cvssScore(source string, cvss map[string]struct {
	V3Score float64 `json:"V3Score"`
	V2Score float64 `json:"V2Score"`
}) float64 {
	if c, ok := cvss[source]; ok && c.V3Score > 0 {
		return c.V3Score
	}
	if c, ok := cvss["nvd"]; ok && c.V3Score > 0 {
		return c.V3Score
	}
	best := 0.0
	for _, c := range cvss {
		best = max(best, c.V3Score)
	}
	return best
}

// writeDockerConfig écrit les identifiants de registre dans un répertoire
// privé (0700, fichier 0600) que seul trivy lit, par DOCKER_CONFIG.
// checkDockerConfig vérifie le format dockerconfigjson des identifiants.
func checkDockerConfig(auth string) error {
	var probe struct {
		Auths map[string]json.RawMessage `json:"auths"`
	}
	if err := json.Unmarshal([]byte(auth), &probe); err != nil || probe.Auths == nil {
		return errors.New("scanner.registryAuth : JSON dockerconfigjson attendu ({\"auths\": {…}})")
	}
	return nil
}

func writeDockerConfig(dir, auth string) error {
	if err := checkDockerConfig(auth); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "config.json"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// Un fichier déjà présent garde son mode à l'ouverture : on le resserre.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(auth); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
