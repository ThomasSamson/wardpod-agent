package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ThomasSamson/wardpod-agent/model"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// sbomLoader : une source capable de fournir le SBOM des images qu'elle
// rapporte.
type sbomLoader interface {
	// sbomRefs désigne, par digest, de quoi charger le SBOM de chaque image
	// des rapports. Un changement de version provoque un nouveau chargement.
	sbomRefs(reports []SourceReport) map[string]sbomRef
	// loadSBOM lit les composants d'un SBOM.
	loadSBOM(ctx context.Context, c *Collector, ref sbomRef) ([]model.Component, error)
}

// sbomRef désigne le SBOM d'une image : un SbomReport (namespace, nom) pour
// l'opérateur, un fichier du cache pour le scanner intégré.
type sbomRef struct {
	namespace, name string
	version         string
}

type sbomEntry struct {
	ref         sbomRef
	loadedRef   sbomRef // ref du contenu chargé
	fingerprint string
	components  []model.Component
	failedAt    time.Time
	loading     bool
}

// needsLoad : jamais chargé, ou chargé depuis une autre version, et pas en
// attente après un échec.
func (e *sbomEntry) needsLoad(now time.Time, retry time.Duration) bool {
	if e.loading || (e.fingerprint != "" && e.loadedRef == e.ref) {
		return false
	}
	return e.failedAt.IsZero() || now.Sub(e.failedAt) >= retry
}

// inventory garde le SBOM des images en service, par digest, et les charge
// en tâche de fond : un SbomReport complet se lit à la demande, une fois
// par image, plutôt que d'être gardé en mémoire par un informer (une
// centaine de mégaoctets pour une centaine d'images). Seuls les champs
// utiles sont gardés.
type inventory struct {
	load   func(ctx context.Context, ref sbomRef) ([]model.Component, error)
	retry  time.Duration
	notify func()
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]*sbomEntry
	wanted  map[string]bool
	// wantAll transmet tous les SBOM connus (mode -dump).
	wantAll bool
	wake    chan struct{}
	// document fournit le SBOM complet compressé d'une image, joint aux
	// lots quand le serveur recherche les vulnérabilités ; nil : aucun.
	document func(digest string, ref sbomRef) ([]byte, error)
}

func newInventory(load func(context.Context, sbomRef) ([]model.Component, error), retry time.Duration, notify func()) *inventory {
	return &inventory{load: load, retry: retry, notify: notify, now: time.Now,
		entries: map[string]*sbomEntry{}, wanted: map[string]bool{}, wake: make(chan struct{}, 1)}
}

func (inv *inventory) signal() {
	select {
	case inv.wake <- struct{}{}:
	default:
	}
}

// update déclare les images en service ; les autres sont oubliées.
func (inv *inventory) update(refs map[string]sbomRef) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	now := inv.now()
	work := false
	for d, ref := range refs {
		e, ok := inv.entries[d]
		if !ok {
			e = &sbomEntry{}
			inv.entries[d] = e
		}
		if e.ref != ref {
			e.ref, e.failedAt = ref, time.Time{}
		}
		work = work || e.needsLoad(now, inv.retry)
	}
	for d, e := range inv.entries {
		if _, ok := refs[d]; !ok && !e.loading {
			delete(inv.entries, d)
		}
	}
	if work {
		inv.signal()
	}
}

// next choisit un SBOM à charger, par ordre de digest.
func (inv *inventory) next() (string, sbomRef, bool) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	now := inv.now()
	var digests []string
	for d, e := range inv.entries {
		if e.needsLoad(now, inv.retry) {
			digests = append(digests, d)
		}
	}
	if len(digests) == 0 {
		return "", sbomRef{}, false
	}
	sort.Strings(digests)
	e := inv.entries[digests[0]]
	e.loading = true
	return digests[0], e.ref, true
}

// run charge les SBOM, un à la fois, jusqu'à l'annulation du contexte. Les
// échecs sont réessayés après retry (au plus tard à l'envoi périodique).
func (inv *inventory) run(ctx context.Context) {
	for {
		digest, ref, ok := inv.next()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-inv.wake:
			case <-time.After(inv.retry):
			}
			continue
		}
		cs, err := inv.load(ctx, ref)
		if err == nil {
			cs = model.NormalizeComponents(cs)
		}
		inv.mu.Lock()
		// update ne retire pas une entrée en cours de chargement.
		e := inv.entries[digest]
		e.loading = false
		if err != nil {
			e.failedAt = inv.now()
		} else {
			e.loadedRef, e.components, e.fingerprint, e.failedAt = ref, cs, model.Fingerprint(cs), time.Time{}
		}
		inv.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if apierrors.IsNotFound(err) {
				slog.Debug("SBOM pas encore disponible", "image", digest, "report", ref.namespace+"/"+ref.name)
			} else {
				slog.Warn("lecture du SBOM d'une image", "image", digest, "err", err)
			}
			continue
		}
		// Une nouvelle empreinte est à déclarer au serveur.
		inv.notify()
	}
}

// declared renvoie l'empreinte du SBOM de chaque image dont il est connu.
func (inv *inventory) declared() []model.ImageSBOM {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	out := []model.ImageSBOM{}
	for d, e := range inv.entries {
		if e.fingerprint != "" {
			out = append(out, model.ImageSBOM{Digest: d, Fingerprint: e.fingerprint})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out
}

// sboms renvoie au plus max SBOM parmi ceux que le serveur a demandés.
func (inv *inventory) sboms(max int) []model.SBOM {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	var digests []string
	for d, e := range inv.entries {
		if e.fingerprint != "" && (inv.wantAll || inv.wanted[d]) {
			digests = append(digests, d)
		}
	}
	sort.Strings(digests)
	if !inv.wantAll && len(digests) > max {
		digests = digests[:max]
	}
	out := make([]model.SBOM, 0, len(digests))
	refs := make([]sbomRef, 0, len(digests))
	for _, d := range digests {
		e := inv.entries[d]
		out = append(out, model.SBOM{Digest: d, Fingerprint: e.fingerprint, Components: e.components})
		refs = append(refs, e.loadedRef)
	}
	if inv.document == nil {
		return out
	}
	// Lecture du cache hors du verrou : quelques mégaoctets par lot.
	inv.mu.Unlock()
	defer inv.mu.Lock()
	for i := range out {
		doc, err := inv.document(out[i].Digest, refs[i])
		if err != nil {
			slog.Warn("SBOM complet indisponible : le serveur le redemandera", "image", out[i].Digest, "err", err)
			continue
		}
		out[i].Document = doc
	}
	return out
}

// sent retire des demandes les SBOM transmis : le snapshot suivant
// redemandera ceux que le serveur n'a pas retenus.
func (inv *inventory) sent(sboms []model.SBOM) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for _, sb := range sboms {
		delete(inv.wanted, sb.Digest)
	}
}

// dumping indique le mode -dump : tous les SBOM partent dans le snapshot.
func (inv *inventory) dumping() bool {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return inv.wantAll
}

// setWanted enregistre les images demandées par le serveur et indique si
// l'une d'elles peut être transmise dès maintenant.
func (inv *inventory) setWanted(digests []string) bool {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.wanted = make(map[string]bool, len(digests))
	ready := false
	for _, d := range digests {
		inv.wanted[d] = true
		if e, ok := inv.entries[d]; ok && e.fingerprint != "" {
			ready = true
		}
	}
	return ready
}

// pending indique qu'un SBOM attend son premier chargement (mode -dump).
func (inv *inventory) pending() bool {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for _, e := range inv.entries {
		if e.fingerprint == "" && e.failedAt.IsZero() {
			return true
		}
	}
	return false
}

// cdxComponent reprend les champs utiles d'un composant CycloneDX, tel que
// trivy le produit.
type cdxComponent struct {
	BOMRef   string `json:"bom-ref"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	PURL     string `json:"purl"`
	Licenses []struct {
		License struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
		Expression string `json:"expression"`
	} `json:"licenses"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
	Components []cdxComponent `json:"components"`
}

type cdxBOM struct {
	Components   []cdxComponent `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

// applications rattache chaque dépendance à son application, par
// bom-ref : celles qu'une application du SBOM (fichier de verrouillage,
// binaire Go) atteint dans le graphe des dépendances, la plus proche
// d'abord.
func applications(bom *cdxBOM, all []*cdxComponent) map[string]string {
	deps := make(map[string][]string, len(bom.Dependencies))
	for _, d := range bom.Dependencies {
		deps[d.Ref] = d.DependsOn
	}
	out := map[string]string{}
	for _, c := range all {
		if c.Type != "application" || c.BOMRef == "" || c.Name == "" {
			continue
		}
		queue := append([]string(nil), deps[c.BOMRef]...)
		seen := map[string]bool{c.BOMRef: true}
		for len(queue) > 0 {
			ref := queue[0]
			queue = queue[1:]
			if seen[ref] {
				continue
			}
			seen[ref] = true
			if _, ok := out[ref]; !ok {
				out[ref] = c.Name
			}
			queue = append(queue, deps[ref]...)
		}
	}
	return out
}

// nodeApplication : un paquet npm installé (sans fichier de verrouillage)
// appartient au paquet installé au premier niveau de node_modules
// (« usr/local/lib/node_modules/npm ») ; ce paquet-là est l'application.
func nodeApplication(filePath string) string {
	const marker = "node_modules/"
	i := strings.Index(filePath, marker)
	if i < 0 {
		return ""
	}
	rest := filePath[i+len(marker):]
	parts := strings.SplitN(rest, "/", 3)
	n := 1
	if strings.HasPrefix(parts[0], "@") {
		n = 2
	}
	if len(parts) <= n {
		return ""
	}
	root := filePath[:i+len(marker)] + strings.Join(parts[:n], "/")
	if filePath == root+"/package.json" {
		return ""
	}
	return root
}

// componentsOf aplatit les composants CycloneDX qui portent un purl : sans
// purl (le système, un fichier de dépendances), un composant n'a pas
// d'identité. Les propriétés de couche ne sont pas gardées.
func componentsOf(bom *cdxBOM) []model.Component {
	var all []*cdxComponent
	var flatten func([]cdxComponent)
	flatten = func(cs []cdxComponent) {
		for i := range cs {
			all = append(all, &cs[i])
			flatten(cs[i].Components)
		}
	}
	flatten(bom.Components)
	apps := applications(bom, all)
	var out []model.Component
	for _, c := range all {
		if c.PURL == "" {
			continue
		}
		mc := model.Component{PURL: c.PURL, Application: apps[c.BOMRef]}
		for _, p := range c.Properties {
			switch p.Name {
			case "aquasecurity:trivy:PkgType":
				mc.Type = p.Value
			case "aquasecurity:trivy:FilePath":
				if mc.Application == "" {
					mc.Application = nodeApplication(p.Value)
				}
			}
		}
		for _, l := range c.Licenses {
			switch {
			case l.License.ID != "":
				mc.Licenses = append(mc.Licenses, l.License.ID)
			case l.License.Name != "":
				mc.Licenses = append(mc.Licenses, l.License.Name)
			case l.Expression != "":
				mc.Licenses = append(mc.Licenses, l.Expression)
			}
		}
		out = append(out, mc)
	}
	return out
}

// parseCycloneDX lit les composants d'un SBOM CycloneDX en JSON.
func parseCycloneDX(data []byte) ([]model.Component, error) {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("SBOM CycloneDX illisible : %w", err)
	}
	return componentsOf(&bom), nil
}

var gvrSbomReports = schema.GroupVersionResource{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "sbomreports"}

// sbomRefs : le SbomReport d'un workload porte le même nom que son
// VulnerabilityReport. Pour une image citée par plusieurs rapports, le plus
// récent est retenu ; sa date de mise à jour sert de version.
func (*OperatorSource) sbomRefs(reports []SourceReport) map[string]sbomRef {
	type cand struct {
		ref sbomRef
		at  time.Time
	}
	best := map[string]cand{}
	for _, r := range reports {
		d := r.Report.Digest
		if d == "" || r.object.name == "" {
			continue
		}
		c := cand{sbomRef{r.object.namespace, r.object.name, r.Report.UpdatedAt.UTC().Format(time.RFC3339Nano)}, r.Report.UpdatedAt}
		cur, ok := best[d]
		if !ok || c.at.After(cur.at) || (c.at.Equal(cur.at) && c.ref.namespace+"/"+c.ref.name < cur.ref.namespace+"/"+cur.ref.name) {
			best[d] = c
		}
	}
	out := make(map[string]sbomRef, len(best))
	for d, c := range best {
		out[d] = c.ref
	}
	return out
}

// loadSBOM lit un SbomReport complet, puis n'en garde que les composants.
func (*OperatorSource) loadSBOM(ctx context.Context, c *Collector, ref sbomRef) ([]model.Component, error) {
	b, err := sbomReportBOM(ctx, c, ref)
	if err != nil {
		return nil, err
	}
	return parseCycloneDX(b)
}

// sbomReportBOM lit le SBOM CycloneDX (JSON) d'un SbomReport.
func sbomReportBOM(ctx context.Context, c *Collector, ref sbomRef) ([]byte, error) {
	u, err := c.dyn.Resource(gvrSbomReports).Namespace(ref.namespace).Get(ctx, ref.name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	raw, ok, _ := unstructured.NestedFieldNoCopy(u.Object, "report", "components")
	if !ok {
		return nil, fmt.Errorf("SbomReport %s/%s sans composants", ref.namespace, ref.name)
	}
	return json.Marshal(raw)
}

// ServerMatch : la source lit les SbomReport, le serveur y cherche les
// vulnérabilités.
func (s *OperatorSource) ServerMatch() bool { return s.serverMatch }

// sbomDocument relit le SbomReport d'une image et le renvoie compressé :
// le SBOM complet envoyé au serveur.
func (*OperatorSource) sbomDocument(ctx context.Context, c *Collector, _ string, ref sbomRef) ([]byte, error) {
	b, err := sbomReportBOM(ctx, c, ref)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > model.MaxDocumentBytes {
		return nil, fmt.Errorf("SBOM complet de %d octets compressés (maximum %d)", buf.Len(), model.MaxDocumentBytes)
	}
	return buf.Bytes(), nil
}

// startInventory lance le chargement des SBOM si l'inventaire est activé
// et que la source en fournit. Avec l'opérateur, il faut pouvoir lire les
// SbomReport ; sans ce droit, l'inventaire est désactivé, pas la collecte.
func (c *Collector) startInventory(ctx context.Context) {
	loader, ok := c.source.(sbomLoader)
	if !c.cfg.Inventory || !ok {
		return
	}
	if _, isOperator := c.source.(*OperatorSource); isOperator {
		if err := c.canGet(ctx, GroupResource{gvrSbomReports.Group, gvrSbomReports.Resource}); err != nil {
			slog.Warn("inventaire logiciel désactivé", "err", err)
			return
		}
	}
	c.inv = newInventory(func(ctx context.Context, ref sbomRef) ([]model.Component, error) {
		ctx, cancel := context.WithTimeout(ctx, c.cfg.APITimeout)
		defer cancel()
		return loader.loadSBOM(ctx, c, ref)
	}, c.cfg.Interval, c.notify)
	if d, ok := c.source.(documentSource); ok && d.ServerMatch() {
		c.inv.document = func(digest string, ref sbomRef) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, c.cfg.APITimeout)
			defer cancel()
			return d.sbomDocument(ctx, c, digest, ref)
		}
	}
	go c.inv.run(ctx)
}

// canGet vérifie que le compte de l'agent peut lire la ressource.
func (c *Collector) canGet(ctx context.Context, gr GroupResource) error {
	review := &authzv1.SelfSubjectAccessReview{Spec: authzv1.SelfSubjectAccessReviewSpec{
		ResourceAttributes: &authzv1.ResourceAttributes{Group: gr.Group, Resource: gr.Resource, Verb: "get"},
	}}
	res, err := c.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("vérification des droits sur %s : %w", gr, err)
	}
	if !res.Status.Allowed {
		return fmt.Errorf("droit \"get\" manquant sur %s", gr)
	}
	return nil
}

// SetWanted enregistre les SBOM demandés par le serveur, à transmettre par
// lots (SBOMUpload) juste après le snapshot.
func (c *Collector) SetWanted(digests []string) {
	if c.inv != nil {
		c.inv.setWanted(digests)
	}
}

// SBOMUpload renvoie le prochain lot de SBOM demandés, au plus
// collect.sbomBatch, ou nil s'il n'y en a plus. En mode -dump, les SBOM
// partent dans le snapshot.
func (c *Collector) SBOMUpload() *model.SBOMUpload {
	if c.inv == nil || c.inv.dumping() {
		return nil
	}
	sboms := c.inv.sboms(c.cfg.SBOMBatch)
	if len(sboms) == 0 {
		return nil
	}
	return &model.SBOMUpload{Version: model.SnapshotVersion, Cluster: c.cfg.Cluster, SBOMs: sboms}
}

// SBOMsSent retire des demandes les SBOM d'un lot transmis.
func (c *Collector) SBOMsSent(up *model.SBOMUpload) {
	if c.inv != nil {
		c.inv.sent(up.SBOMs)
	}
}

// WantAllSBOMs fait transmettre tous les SBOM connus (mode -dump).
func (c *Collector) WantAllSBOMs() {
	if c.inv != nil {
		c.inv.mu.Lock()
		c.inv.wantAll = true
		c.inv.mu.Unlock()
	}
}
