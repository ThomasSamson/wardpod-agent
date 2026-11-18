package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ThomasSamson/wardpod-agent/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

// Source fournit les vulnérabilités des workloads.
type Source interface {
	Name() string
	// Check vérifie que la source est utilisable dans ce cluster.
	Check(ctx context.Context, c *Collector) error
	// Required liste les ressources que la source doit lister et observer.
	Required() []GroupResource
	// Register enregistre ses informers, avant le démarrage du collecteur ;
	// elle appelle c.notify à chaque changement.
	Register(c *Collector) error
	// Reports renvoie les rapports, chacun rattaché à son workload.
	Reports() ([]SourceReport, error)
}

// SourceReport est un rapport de vulnérabilités et le workload qu'il décrit.
type SourceReport struct {
	Workload workloadKey
	Report   model.VulnerabilityReport
	// object désigne le rapport lu (source operator) : VulnerabilityReport,
	// dont le SbomReport porte le même nom, ou SbomReport (serverMatch).
	object struct{ namespace, name string }
}

var gvrVulnReports = schema.GroupVersionResource{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "vulnerabilityreports"}

// OperatorSource lit les VulnerabilityReport du Trivy Operator. Avec
// ServerMatch (scanner.serverMatch), elle lit les SbomReport à leur place :
// le serveur y cherche les vulnérabilités, et l'opérateur peut être réglé
// pour en garder moins dans etcd.
type OperatorSource struct {
	lister      cache.GenericLister
	serverMatch bool
}

// NewOperatorSource construit la source du Trivy Operator.
func NewOperatorSource(serverMatch bool) *OperatorSource {
	return &OperatorSource{serverMatch: serverMatch}
}

func (*OperatorSource) Name() string { return "operator" }

// reports : la ressource lue, VulnerabilityReport ou SbomReport.
func (s *OperatorSource) reports() schema.GroupVersionResource {
	if s.serverMatch {
		return gvrSbomReports
	}
	return gvrVulnReports
}

func (s *OperatorSource) Required() []GroupResource {
	gvr := s.reports()
	return []GroupResource{{gvr.Group, gvr.Resource}}
}

func (s *OperatorSource) Check(_ context.Context, c *Collector) error {
	gvr := s.reports()
	ok, err := c.served(gvr)
	if err != nil {
		return fmt.Errorf("découverte de %s : %w", gvr.Resource, err)
	}
	if !ok {
		return fmt.Errorf("CRD %s absente : le Trivy Operator est-il installé ?", gvr.Resource)
	}
	return nil
}

// stripComponents ne garde d'un SbomReport que son en-tête (image,
// registre, date) : ses composants, jusqu'à quelques mégaoctets par image,
// se relisent à la demande (loadSBOM, sbomDocument).
func stripComponents(obj any) (any, error) {
	obj, err := stripManagedFields(obj)
	if u, ok := obj.(*unstructured.Unstructured); ok {
		unstructured.RemoveNestedField(u.Object, "report", "components")
	}
	return obj, err
}

func (s *OperatorSource) Register(c *Collector) error {
	gvr := s.reports()
	inf := c.dynamicInformer(gvr)
	if s.serverMatch {
		_ = inf.SetTransform(stripComponents)
	}
	s.lister = cache.NewGenericLister(inf.GetIndexer(), gvr.GroupResource())
	_, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { c.notify() },
		UpdateFunc: func(any, any) { c.notify() },
		DeleteFunc: func(any) { c.notify() },
	})
	return err
}

// trivyReport reprend les champs utiles d'un VulnerabilityReport.
type trivyReport struct {
	Artifact struct {
		Digest     string `json:"digest"`
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
	} `json:"artifact"`
	Registry struct {
		Server string `json:"server"`
	} `json:"registry"`
	OS struct {
		Family string `json:"family"`
		Name   string `json:"name"`
	} `json:"os"`
	Scanner struct {
		Version string `json:"version"`
	} `json:"scanner"`
	UpdateTimestamp time.Time `json:"updateTimestamp"`
	Vulnerabilities []struct {
		VulnerabilityID  string   `json:"vulnerabilityID"`
		Resource         string   `json:"resource"`
		InstalledVersion string   `json:"installedVersion"`
		FixedVersion     string   `json:"fixedVersion"`
		Severity         string   `json:"severity"`
		Score            *float64 `json:"score"`
		Title            string   `json:"title"`
		PrimaryLink      string   `json:"primaryLink"`
		Target           string   `json:"target"`
		PackagePURL      string   `json:"packagePURL"`
		PublishedDate    string   `json:"publishedDate"`
	} `json:"vulnerabilities"`
}

const (
	lblKind      = "trivy-operator.resource.kind"
	lblName      = "trivy-operator.resource.name"
	lblNamespace = "trivy-operator.resource.namespace"
	lblContainer = "trivy-operator.container.name"
)

// reportWorkload identifie le workload d'un rapport. Quand son nom n'est pas
// une valeur de label valide (plus de 63 caractères), le Trivy Operator le
// range dans une annotation de même clé.
func reportWorkload(u *unstructured.Unstructured) (workloadKey, bool) {
	l := u.GetLabels()
	key := workloadKey{l[lblNamespace], l[lblKind], l[lblName]}
	if key.Name == "" {
		key.Name = u.GetAnnotations()[lblName]
	}
	if key.Namespace == "" {
		key.Namespace = u.GetNamespace()
	}
	return key, key.Kind != "" && key.Name != ""
}

func (s *OperatorSource) Reports() ([]SourceReport, error) {
	objs, err := s.lister.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	out := make([]SourceReport, 0, len(objs))
	for _, o := range objs {
		u, ok := o.(*unstructured.Unstructured)
		if !ok {
			continue
		}
		key, ok := reportWorkload(u)
		if !ok {
			slog.Warn("rapport sans workload identifiable", "report", u.GetNamespace()+"/"+u.GetName())
			continue
		}
		raw, ok := u.Object["report"]
		if !ok {
			continue
		}
		b, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		var tr trivyReport
		if err := json.Unmarshal(b, &tr); err != nil {
			slog.Warn("rapport illisible", "report", u.GetNamespace()+"/"+u.GetName(), "err", err)
			continue
		}
		// SbomReport (serverMatch) : pas de vulnérabilités, le serveur les
		// cherche dans le SBOM complet.
		r := model.VulnerabilityReport{
			Namespace:       key.Namespace,
			WorkloadKind:    key.Kind,
			WorkloadName:    key.Name,
			Container:       u.GetLabels()[lblContainer],
			Registry:        tr.Registry.Server,
			Repository:      tr.Artifact.Repository,
			Tag:             tr.Artifact.Tag,
			Digest:          tr.Artifact.Digest,
			OSFamily:        tr.OS.Family,
			OSName:          tr.OS.Name,
			ScannerVersion:  tr.Scanner.Version,
			UpdatedAt:       tr.UpdateTimestamp,
			Vulnerabilities: make([]model.Vulnerability, 0, len(tr.Vulnerabilities)),
		}
		for _, v := range tr.Vulnerabilities {
			mv := model.Vulnerability{
				ID: v.VulnerabilityID, Package: v.Resource, InstalledVersion: v.InstalledVersion,
				FixedVersion: v.FixedVersion, Severity: strings.ToUpper(v.Severity), Title: v.Title,
				PrimaryLink: v.PrimaryLink, Target: v.Target, PURL: v.PackagePURL, PublishedDate: v.PublishedDate,
			}
			if v.Score != nil {
				mv.Score = *v.Score
			}
			r.Vulnerabilities = append(r.Vulnerabilities, mv)
		}
		sr := SourceReport{Workload: key, Report: r}
		sr.object.namespace, sr.object.name = u.GetNamespace(), u.GetName()
		out = append(out, sr)
	}
	return out, nil
}
