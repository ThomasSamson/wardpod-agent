package agent

import (
	"context"
	"log/slog"
	"slices"
	"sort"
	"strconv"
	"sync"

	"github.com/ThomasSamson/wardpod-agent/model"
	"github.com/ThomasSamson/wardpod-agent/scanner"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

// BuiltinSource analyse elle-même les images en service, avec le scanner
// intégré, quand le Trivy Operator n'est pas installé. Les rapports qu'elle
// produit ont la même forme que ceux de l'opérateur : la suite du traitement
// ne change pas.
type BuiltinSource struct {
	scanner *scanner.Scanner
	c       *Collector

	mu sync.Mutex
	// last garde les images de chaque (workload, conteneur) vues en
	// service : un CronJob entre deux exécutions, ou un workload réduit à
	// zéro réplica, garde ses vulnérabilités tant qu'il existe, comme avec
	// l'opérateur.
	last map[containerKey]map[string]containerImage
	// unscanned : digests sans résultat (en attente ou en échec) ; pending :
	// ceux qui attendent leur première analyse.
	unscanned []string
	pending   bool
	// unscannable : images sans digest de registre, signalées une fois.
	unscannable map[string]bool
}

type containerKey struct {
	workload  workloadKey
	container string
}

func NewBuiltinSource(s *scanner.Scanner) *BuiltinSource {
	return &BuiltinSource{scanner: s, last: map[containerKey]map[string]containerImage{}, unscannable: map[string]bool{}}
}

func (*BuiltinSource) Name() string { return model.SourceBuiltin }

func (b *BuiltinSource) Check(ctx context.Context, _ *Collector) error { return b.scanner.Check(ctx) }

// Required : les pods et les Jobs, déjà lus pour le contexte.
func (*BuiltinSource) Required() []GroupResource { return nil }

// imageIDs résume la phase d'un pod et les images rapportées par le
// kubelet : ce qui change l'inventaire des images en service.
func imageIDs(p *corev1.Pod) []string {
	ids := []string{string(p.Status.Phase)}
	for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		ids = append(ids, cs.Name+"="+cs.ImageID)
	}
	return ids
}

// Register prévient la collecte quand des pods apparaissent, disparaissent,
// changent de phase ou reçoivent leur image (le kubelet renseigne imageID
// par une mise à jour du statut) ; le scanner la prévient de ses nouveaux
// résultats.
func (b *BuiltinSource) Register(c *Collector) error {
	b.c = c
	_, err := c.typed.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { c.notify() },
		DeleteFunc: func(any) { c.notify() },
		UpdateFunc: func(oldObj, newObj any) {
			o, ok1 := oldObj.(*corev1.Pod)
			n, ok2 := newObj.(*corev1.Pod)
			if !ok1 || !ok2 || !slices.Equal(imageIDs(o), imageIDs(n)) {
				c.notify()
			}
		},
	})
	return err
}

// Unscanned renvoie les digests des images en service sans résultat : le
// serveur ne déclare corrigé aucun de leurs findings.
func (b *BuiltinSource) Unscanned() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.unscanned...)
}

// Pending indique que des images attendent leur première analyse (mode
// -dump).
func (b *BuiltinSource) Pending() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pending
}

// Unscannable compte les images en service sans digest de registre.
func (b *BuiltinSource) Unscannable() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.unscannable)
}

// podWorkload rattache un pod au workload que le Trivy Operator citerait :
// son contrôleur intégré (le CronJob pour un Job qui en dépend), sinon le pod.
func podWorkload(p *corev1.Pod, cronOfJob map[string]string) workloadKey {
	kind, name := controller(p.OwnerReferences)
	switch {
	case kind == "Job" && cronOfJob[p.Namespace+"/"+name] != "":
		return workloadKey{p.Namespace, "CronJob", cronOfJob[p.Namespace+"/"+name]}
	case builtInControllers[kind]:
		return workloadKey{p.Namespace, kind, name}
	}
	return workloadKey{p.Namespace, "Pod", p.Name}
}

type containerImage struct {
	workload  workloadKey
	container string
	image     string // référence déclarée (pour le registre, le dépôt, le tag)
	ref       string // référence à tirer
	digest    string
}

// inService relève les images des pods en service, par (workload,
// conteneur) et par digest : des réplicas peuvent tourner sur des images
// différentes (tag mobile, mise à jour partielle).
func (b *BuiltinSource) inService() (map[containerKey]map[string]containerImage, map[string]bool) {
	c := b.c
	cronOfJob := map[string]string{}
	for _, j := range c.listers.job() {
		if k, n := controller(j.OwnerReferences); k == "CronJob" {
			cronOfJob[j.Namespace+"/"+j.Name] = n
		}
	}
	current := map[containerKey]map[string]containerImage{}
	unscannable := map[string]bool{}
	for _, p := range c.listers.pod() {
		if p.Status.Phase != corev1.PodRunning && p.Status.Phase != corev1.PodPending {
			continue
		}
		wk := podWorkload(p, cronOfJob)
		for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			if cs.ImageID == "" {
				continue // image pas encore tirée
			}
			ref, digest, err := scanner.PullRef(cs.ImageID)
			if err != nil {
				unscannable[cs.ImageID] = true
				if !b.unscannable[cs.ImageID] {
					slog.Warn("image non analysable", "pod", p.Namespace+"/"+p.Name, "container", cs.Name, "image", cs.Image, "err", err)
				}
				continue
			}
			k := containerKey{wk, cs.Name}
			if current[k] == nil {
				current[k] = map[string]containerImage{}
			}
			current[k][digest] = containerImage{workload: wk, container: cs.Name, image: cs.Image, ref: ref, digest: digest}
		}
	}
	return current, unscannable
}

// staleReplicaSets renvoie les ReplicaSet d'un Deployment qui ne portent
// pas sa révision la plus récente : l'historique gardé par Kubernetes.
func (b *BuiltinSource) staleReplicaSets() map[workloadKey]bool {
	type rev struct {
		key workloadKey
		n   int
	}
	newest := map[string]rev{}
	var all []rev
	for _, rs := range b.c.listers.rs() {
		kind, name := controller(rs.OwnerReferences)
		if kind != "Deployment" {
			continue
		}
		n, _ := strconv.Atoi(rs.Annotations["deployment.kubernetes.io/revision"])
		r := rev{workloadKey{rs.Namespace, "ReplicaSet", rs.Name}, n}
		all = append(all, r)
		owner := rs.Namespace + "/" + name
		if cur, ok := newest[owner]; !ok || n > cur.n {
			newest[owner] = r
		}
	}
	stale := map[workloadKey]bool{}
	for _, r := range all {
		stale[r.key] = true
	}
	for _, r := range newest {
		delete(stale, r.key)
	}
	return stale
}

func (b *BuiltinSource) Reports() ([]SourceReport, error) {
	current, unscannable := b.inService()
	existing := b.c.templates()

	stale := b.staleReplicaSets()
	b.mu.Lock()
	// Un (workload, conteneur) sans pod en service garde ses dernières
	// images tant que le workload existe, sauf l'ancien ReplicaSet d'un
	// Deployment mis à jour : sa nouvelle image remplace l'ancienne, dont
	// les vulnérabilités doivent pouvoir être déclarées corrigées.
	for k, imgs := range b.last {
		if _, ok := current[k]; !ok {
			if _, exists := existing[k.workload]; exists && !stale[k.workload] {
				current[k] = imgs
			}
		}
	}
	b.last = current
	b.unscannable = unscannable
	b.mu.Unlock()

	var items []containerImage
	for _, imgs := range current {
		for _, it := range imgs {
			items = append(items, it)
		}
	}
	wanted := make([]scanner.Image, 0, len(items))
	for _, it := range items {
		wanted = append(wanted, scanner.Image{Digest: it.digest, Ref: it.ref, Priority: 1})
	}
	b.scanner.Want(wanted)

	pending := false
	unscanned := map[string]bool{}
	out := make([]SourceReport, 0, len(items))
	for _, it := range items {
		if b.scanner.Excluded(it.ref) {
			continue
		}
		res, lastErr, ok := b.scanner.Result(it.digest)
		if !ok {
			// En attente ou en échec : ses vulnérabilités ne sont pas
			// connues, le serveur garde celles qu'il a.
			unscanned[it.digest] = true
			if lastErr == "" {
				pending = true
			}
			continue
		}
		registry, repository, tag := scanner.SplitImage(it.image)
		out = append(out, SourceReport{Workload: it.workload, Report: model.VulnerabilityReport{
			Namespace: it.workload.Namespace, WorkloadKind: it.workload.Kind, WorkloadName: it.workload.Name,
			Container: it.container, Registry: registry, Repository: repository, Tag: tag, Digest: it.digest,
			OSFamily: res.OSFamily, OSName: res.OSName, ScannerVersion: "trivy (intégré)", UpdatedAt: res.ScannedAt,
			Vulnerabilities: res.Vulns,
		}})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Report, out[j].Report
		return a.Namespace+a.WorkloadKind+a.WorkloadName+a.Container+a.Digest < b.Namespace+b.WorkloadKind+b.WorkloadName+b.Container+b.Digest
	})
	list := make([]string, 0, len(unscanned))
	for d := range unscanned {
		list = append(list, d)
	}
	sort.Strings(list)
	b.mu.Lock()
	b.unscanned, b.pending = list, pending
	b.mu.Unlock()
	return out, nil
}

// sbomRefs : le SBOM de chaque image analysée est dans le cache du
// scanner ; il ne change pas pour un même digest.
func (*BuiltinSource) sbomRefs(reports []SourceReport) map[string]sbomRef {
	out := map[string]sbomRef{}
	for _, r := range reports {
		if d := r.Report.Digest; d != "" {
			out[d] = sbomRef{name: d}
		}
	}
	return out
}

func (b *BuiltinSource) loadSBOM(_ context.Context, _ *Collector, ref sbomRef) ([]model.Component, error) {
	data, err := b.scanner.SBOM(ref.name)
	if err != nil {
		return nil, err
	}
	return parseCycloneDX(data)
}

// documentSource fournit les SBOM complets quand le serveur recherche les
// vulnérabilités (scanner.serverMatch).
type documentSource interface {
	ServerMatch() bool
	sbomDocument(ctx context.Context, c *Collector, digest string, ref sbomRef) ([]byte, error)
}

// ServerMatch : le scanner ne fait que les SBOM, le serveur y cherche les
// vulnérabilités.
func (b *BuiltinSource) ServerMatch() bool { return b.scanner != nil && b.scanner.ServerMatch() }

// sbomDocument renvoie le SBOM CycloneDX en cache d'une image, tel quel :
// le cache est déjà compressé.
func (b *BuiltinSource) sbomDocument(_ context.Context, _ *Collector, digest string, _ sbomRef) ([]byte, error) {
	return b.scanner.SBOMCompressed(digest, model.MaxDocumentBytes)
}
