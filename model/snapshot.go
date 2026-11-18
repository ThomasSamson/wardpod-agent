// Package model définit le contrat échangé entre l'agent (un par cluster) et
// le serveur central. Un snapshot décrit l'état complet d'un cluster à un
// instant donné : le serveur en déduit les apparitions et disparitions.
package model

import (
	"fmt"
	"regexp"
	"time"
)

const SnapshotVersion = 1

var clusterName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidClusterName impose un nom DNS court : il apparaît dans les URL, les
// métriques et les noms de ressources.
func ValidClusterName(name string) error {
	if !clusterName.MatchString(name) {
		return fmt.Errorf("nom de cluster invalide %q : minuscules, chiffres et tirets, 63 caractères au plus", name)
	}
	return nil
}

// Sources des vulnérabilités d'un snapshot.
const (
	SourceOperator = "operator"
	SourceBuiltin  = "builtin"
)

type Snapshot struct {
	Version      int    `json:"version"`
	Cluster      string `json:"cluster"`
	Environment  string `json:"environment"`
	AgentVersion string `json:"agentVersion"`
	// Source indique l'origine des vulnérabilités : "operator" (Trivy
	// Operator) ou "builtin" (scanner intégré). Champ ajouté sans rupture :
	// vide, il vaut "operator".
	Source string `json:"source,omitempty"`
	// AgentInstance identifie le processus émetteur (nom du pod) : deux
	// agents qui partagent un jeton sont ainsi repérés.
	AgentInstance string `json:"agentInstance,omitempty"`
	// Unscanned liste les digests des images en service dont les
	// vulnérabilités manquent (analyse en attente ou en échec, scanner
	// intégré) : le serveur ne déclare corrigé aucun de leurs findings.
	// Champ ajouté sans rupture.
	Unscanned []string `json:"unscanned,omitempty"`
	// ServerMatch : les rapports n'ont pas de vulnérabilités, le serveur les
	// recherche dans les SBOM complets reçus (scanner.serverMatch). Champ
	// ajouté sans rupture.
	ServerMatch bool `json:"serverMatch,omitempty"`
	// Inventory déclare l'empreinte du SBOM des images dont l'agent le
	// connaît ; SBOMs transmet les composants de celles que le serveur a
	// demandées. Champs ajoutés sans rupture.
	Inventory   []ImageSBOM           `json:"inventory,omitempty"`
	SBOMs       []SBOM                `json:"sboms,omitempty"`
	CollectedAt time.Time             `json:"collectedAt"`
	Workloads   []Workload            `json:"workloads"`
	Reports     []VulnerabilityReport `json:"reports"`
}

// Exposure indique jusqu'où un workload est joignable.
type Exposure string

const (
	ExposureNone     Exposure = "none"     // aucun Service ne le sélectionne
	ExposureCluster  Exposure = "cluster"  // joignable depuis le cluster (ClusterIP)
	ExposureInternet Exposure = "internet" // Ingress, HTTPRoute, IngressRoute, LoadBalancer, NodePort, hostPort
)

func (e Exposure) Rank() int {
	switch e {
	case ExposureInternet:
		return 2
	case ExposureCluster:
		return 1
	}
	return 0
}

// Workload est la ressource que Trivy a scannée (son contrôleur direct :
// ReplicaSet, DaemonSet, StatefulSet, Job, CronJob, Pod), complétée du
// propriétaire lisible (Deployment pour un ReplicaSet).
type Workload struct {
	Namespace  string      `json:"namespace"`
	Kind       string      `json:"kind"`
	Name       string      `json:"name"`
	OwnerKind  string      `json:"ownerKind,omitempty"`
	OwnerName  string      `json:"ownerName,omitempty"`
	Running    bool        `json:"running"`
	Exposure   Exposure    `json:"exposure"`
	ExposedVia []string    `json:"exposedVia,omitempty"`
	Containers []Container `json:"containers"`
}

type Container struct {
	Name     string          `json:"name"`
	Image    string          `json:"image"`
	Security SecurityContext `json:"security"`
}

type SecurityContext struct {
	Privileged     bool `json:"privileged,omitempty"`
	HostNamespaces bool `json:"hostNamespaces,omitempty"` // hostNetwork, hostPID ou hostIPC
	HostPath       bool `json:"hostPath,omitempty"`
	RootPossible   bool `json:"rootPossible,omitempty"` // runAsNonRoot absent et runAsUser absent ou 0
	PrivEscalation bool `json:"privEscalation,omitempty"`
	// RootExplicit (runAsUser: 0) et PrivEscalationExplicit
	// (allowPrivilegeEscalation: true) distinguent une dégradation écrite
	// dans le manifeste des valeurs par défaut de Kubernetes.
	RootExplicit           bool     `json:"rootExplicit,omitempty"`
	PrivEscalationExplicit bool     `json:"privEscalationExplicit,omitempty"`
	DangerousCaps          []string `json:"dangerousCaps,omitempty"`
	ReadOnlyRootFS         bool     `json:"readOnlyRootFS,omitempty"`
	AutomountSAToken       bool     `json:"automountSAToken,omitempty"`
}

type VulnerabilityReport struct {
	Namespace       string          `json:"namespace"`
	WorkloadKind    string          `json:"workloadKind"`
	WorkloadName    string          `json:"workloadName"`
	Container       string          `json:"container"`
	Registry        string          `json:"registry"`
	Repository      string          `json:"repository"`
	Tag             string          `json:"tag"`
	Digest          string          `json:"digest"`
	OSFamily        string          `json:"osFamily,omitempty"`
	OSName          string          `json:"osName,omitempty"`
	ScannerVersion  string          `json:"scannerVersion,omitempty"`
	UpdatedAt       time.Time       `json:"updatedAt"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	ID               string  `json:"id"`
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installedVersion"`
	FixedVersion     string  `json:"fixedVersion,omitempty"`
	Severity         string  `json:"severity"`
	Score            float64 `json:"score,omitempty"`
	Title            string  `json:"title,omitempty"`
	PrimaryLink      string  `json:"primaryLink,omitempty"`
	Target           string  `json:"target,omitempty"`
	PURL             string  `json:"purl,omitempty"`
	PublishedDate    string  `json:"publishedDate,omitempty"`
}
