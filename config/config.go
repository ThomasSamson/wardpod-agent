// Package config porte la configuration de l'agent : défauts, puis YAML
// facultatif (WP_CONFIG), puis variables WP_*, puis flags. Les noms de
// variables et de flags sont déduits des chemins (fields.go).
package config

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"time"
)

// Config : configuration de l'agent.
type Config struct {
	Log Log `yaml:"log"`
	// ShutdownTimeout borne l'arrêt propre après SIGTERM.
	ShutdownTimeout time.Duration `yaml:"shutdownTimeout"`
	Collect         Collect       `yaml:"collect"`
	Scanner         Scanner       `yaml:"scanner"`
	Agent           Agent         `yaml:"agent"`
	MCP             MCP           `yaml:"mcp"`
}

// DefaultShutdownTimeout : délai d'arrêt propre par défaut.
const DefaultShutdownTimeout = 25 * time.Second

// Default renvoie la configuration par défaut de l'agent.
func Default() Config {
	return Config{Log: DefaultLog(), ShutdownTimeout: DefaultShutdownTimeout, Collect: DefaultCollect(), Scanner: DefaultScanner(), Agent: DefaultAgent(), MCP: DefaultMCP()}
}

// DefaultLog : journal en JSON, niveau info.
func DefaultLog() Log { return Log{Level: "info", Format: "json"} }

// DefaultCollect : valeurs par défaut de la section collect.
func DefaultCollect() Collect {
	return Collect{
		Interval:            10 * time.Minute,
		Debounce:            30 * time.Second,
		SyncTimeout:         2 * time.Minute,
		APITimeout:          30 * time.Second,
		RetryInterval:       15 * time.Second,
		Source:              "auto",
		SourceCheckInterval: 5 * time.Minute,
		InternalLoadBalancerAnnotations: []string{
			"service.beta.kubernetes.io/aws-load-balancer-internal=true",
			"service.beta.kubernetes.io/aws-load-balancer-scheme=internal",
			"networking.gke.io/load-balancer-type=Internal",
			"cloud.google.com/load-balancer-type=Internal",
			"service.beta.kubernetes.io/azure-load-balancer-internal=true",
			"service.beta.kubernetes.io/openstack-internal-load-balancer=true",
			"service.beta.kubernetes.io/scw-loadbalancer-private=true",
			"lb.stackit.cloud/internal-lb=true",
		},
		InternalGateways:       []string{},
		InternalGatewayClasses: []string{},
		Inventory:              true,
		SBOMBatch:              20,
	}
}

// DefaultScanner : valeurs par défaut de la section scanner.
func DefaultScanner() Scanner {
	return Scanner{
		TrivyPath:        "trivy",
		CacheDir:         "/var/cache/wardpod",
		DBRepository:     []string{},
		JavaDBRepository: []string{},
		DBUpdateInterval: 12 * time.Hour,
		Concurrency:      2,
		Timeout:          10 * time.Minute,
		MaxImageSize:     "",
		RetryInterval:    time.Hour,
		MaxRetryInterval: 24 * time.Hour,
		Exclude:          []string{},
		SBOMRetention:    7 * 24 * time.Hour,
		RuntimeEnv: map[string]string{"PHP_VERSION": "php", "NODE_VERSION": "node", "PYTHON_VERSION": "python", "JAVA_VERSION": "java",
			"GOLANG_VERSION": "go", "RUBY_VERSION": "ruby", "DOTNET_VERSION": "dotnet", "ASPNETCORE_VERSION": "aspnetcore", "PERL_VERSION": "perl"},
	}
}

// DefaultAgent : valeurs par défaut de la section agent.
func DefaultAgent() Agent {
	return Agent{
		HTTPTimeout: time.Minute,
		Listen:      ":8081",
	}
}

// DefaultMCP : valeurs par défaut de la section mcp.
func DefaultMCP() MCP { return MCP{HTTPTimeout: 30 * time.Second} }

// Load lit la configuration : défauts, fichier WP_CONFIG, puis variables
// WP_*. Elle renvoie aussi les variables WP_* inconnues.
func Load(environ []string) (Config, []string, error) {
	c := Default()
	unknown, err := LoadInto(&c, environ)
	return c, unknown, err
}

// Fields énumère les clés de c dans l'ordre de déclaration.
func (c *Config) Fields() []Field { return Fields(c) }

// RegisterFlags déclare un flag par clé (voir RegisterFlags).
func (c *Config) RegisterFlags(fs *flag.FlagSet) { d := Default(); RegisterFlags(fs, c, &d) }

// Redacted rend la configuration effective en YAML, secrets masqués.
func (c *Config) Redacted() ([]byte, error) { return Redacted(c) }

// ValidateCommon vérifie les clés communes : journal et délai d'arrêt.
func (c *Config) ValidateCommon() error { return ValidateBase(c.Log, c.ShutdownTimeout) }

// ValidateBase vérifie le journal et le délai d'arrêt.
func ValidateBase(log Log, shutdownTimeout time.Duration) error {
	var errs []error
	if _, err := ParseLevel(log.Level); err != nil {
		errs = append(errs, err)
	}
	if log.Format != "json" && log.Format != "text" {
		errs = append(errs, fmt.Errorf("log.format : json ou text attendu (%q)", log.Format))
	}
	if shutdownTimeout <= 0 {
		errs = append(errs, fmt.Errorf("shutdownTimeout doit être positif (%s)", shutdownTimeout))
	}
	return errors.Join(errs...)
}

type Log struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, text
}

// Collect règle la collecte dans un cluster (agent, et serveur ou mode
// autonome qui collectent leur propre cluster).
type Collect struct {
	Cluster     string `yaml:"cluster"`
	Environment string `yaml:"environment"`
	// KubeContext choisit un contexte du kubeconfig hors du cluster ; vide,
	// la configuration in-cluster ou le contexte courant s'applique.
	KubeContext string        `yaml:"kubeContext"`
	Interval    time.Duration `yaml:"interval"`
	Debounce    time.Duration `yaml:"debounce"`
	SyncTimeout time.Duration `yaml:"syncTimeout"`
	// APITimeout borne chaque requête à l'API Kubernetes (hors watch).
	APITimeout time.Duration `yaml:"apiTimeout"`
	// RetryInterval est le premier délai avant un nouvel essai après un
	// envoi en échec ; il double à chaque échec, sans dépasser Interval. Un
	// Retry-After du serveur est respecté.
	RetryInterval time.Duration `yaml:"retryInterval"`
	// Source des vulnérabilités : auto (le Trivy Operator s'il est installé
	// et lisible, sinon le scanner intégré), operator ou builtin.
	Source string `yaml:"source"`
	// SourceCheckInterval espace les réévaluations de la source en mode
	// auto : installer ou retirer l'opérateur bascule sans redémarrage.
	SourceCheckInterval time.Duration `yaml:"sourceCheckInterval"`
	// InternalLoadBalancerAnnotations reconnaissent un load balancer interne,
	// sous la forme clé=valeur (valeur sans casse) : sur un Service
	// LoadBalancer, ou dans spec.infrastructure.annotations d'une Gateway. Le
	// workload est alors exposé au cluster, pas sur internet.
	InternalLoadBalancerAnnotations []string `yaml:"internalLoadBalancerAnnotations"`
	// InternalGateways (namespace/nom) et InternalGatewayClasses désignent
	// les Gateways joignables du seul réseau privé. Une route n'est interne
	// que si toutes ses Gateways le sont.
	InternalGateways       []string `yaml:"internalGateways"`
	InternalGatewayClasses []string `yaml:"internalGatewayClasses"`
	// Inventory transmet l'inventaire logiciel des images (leur SBOM) au
	// serveur. SBOMBatch borne le nombre de SBOM complets par lot
	// (POST /api/v1/sboms) : les lots partent à la suite, après le snapshot.
	Inventory bool `yaml:"inventory"`
	SBOMBatch int  `yaml:"sbomBatch"`
}

// Scanner règle le scanner intégré, qui pilote le binaire trivy.
type Scanner struct {
	TrivyPath string `yaml:"trivyPath"`
	// CacheDir garde la base de vulnérabilités et les SBOM : un cache
	// jetable (facteur VI), qui évite de retélécharger.
	CacheDir string `yaml:"cacheDir"`
	// DBRepository et JavaDBRepository désignent des miroirs des bases de
	// Trivy (environnements isolés) ; vides, ceux de Trivy.
	DBRepository     []string `yaml:"dbRepository"`
	JavaDBRepository []string `yaml:"javaDBRepository"`
	// DBUpdateInterval espace les mises à jour de la base ; après chacune,
	// les SBOM connus sont réévalués sans retélécharger les images.
	DBUpdateInterval time.Duration `yaml:"dbUpdateInterval"`
	// Concurrency : analyses d'images simultanées.
	Concurrency int `yaml:"concurrency"`
	// Timeout borne l'analyse d'une image ; MaxImageSize la refuse au-delà
	// (format de Trivy : 2GB, 500MB ; vide, pas de limite).
	Timeout      time.Duration `yaml:"timeout"`
	MaxImageSize string        `yaml:"maxImageSize"`
	// RetryInterval : premier délai avant de réessayer une image en échec,
	// doublé à chaque échec jusqu'à MaxRetryInterval.
	RetryInterval    time.Duration `yaml:"retryInterval"`
	MaxRetryInterval time.Duration `yaml:"maxRetryInterval"`
	// RegistryAuth : identifiants des registres privés au format
	// dockerconfigjson, chargés depuis un Secret. Secret.
	RegistryAuth string `yaml:"registryAuth" secret:"true"`
	// Exclude : images jamais analysées (motifs path.Match sur la
	// référence, par exemple "registry.internal/sandbox/*").
	Exclude []string `yaml:"exclude"`
	// SBOMRetention : le SBOM d'une image qui ne tourne plus est gardé ce
	// temps en cache (elle peut revenir), puis supprimé.
	SBOMRetention time.Duration `yaml:"sbomRetention"`
	// RuntimeEnv : variables de la configuration de l'image qui donnent la
	// version d'un runtime (PHP_VERSION → php) ; trivy ne voit pas un
	// runtime compilé dans l'image, il s'ajoute au SBOM comme composant
	// pkg:generic/<runtime>@<version>, de type runtime.
	RuntimeEnv map[string]string `yaml:"runtimeEnv"`
	// ServerMatch : l'agent ne fait que les SBOM, sans base de
	// vulnérabilités ; il les envoie complets et la console y cherche les
	// vulnérabilités (si elle le propose).
	ServerMatch bool `yaml:"serverMatch"`
}

// Agent règle l'envoi des snapshots au serveur central.
type Agent struct {
	ServerURL     string        `yaml:"serverURL"`
	Token         string        `yaml:"token" secret:"true"`
	AllowInsecure bool          `yaml:"allowInsecure"`
	HTTPTimeout   time.Duration `yaml:"httpTimeout"`
	// Listen sert les sondes /healthz et /readyz.
	Listen string `yaml:"listen"`
}

// MCP règle la sous-commande mcp : serveur MCP local qui donne à un
// assistant IA l'accès à la console par un jeton d'API personnel.
type MCP struct {
	URL           string        `yaml:"url"`
	Token         string        `yaml:"token" secret:"true"`
	AllowInsecure bool          `yaml:"allowInsecure"`
	HTTPTimeout   time.Duration `yaml:"httpTimeout"`
}

func CheckURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("URL invalide (%q)", RedactURL(raw))
	}
	if u.User != nil {
		return errors.New("identifiants interdits dans l'URL : ils apparaîtraient dans les logs")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); allowInsecure || host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("URL en http:// (%s) : les échanges circuleraient en clair, utiliser https:// ou l'option allowInsecure", u.Host)
	}
	return fmt.Errorf("schéma non pris en charge (%q)", u.Scheme)
}

// RedactURL masque le mot de passe éventuel d'une URL.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	return u.Redacted()
}

func ParseLevel(s string) (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return l, fmt.Errorf("log.level : debug, info, warn ou error attendu (%q)", s)
	}
	return l, nil
}
