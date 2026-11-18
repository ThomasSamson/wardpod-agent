// Package agent collecte l'état d'un cluster : vulnérabilités (par une
// Source), contexte des workloads (exposition, securityContext), puis remet
// un snapshot complet à une Destination. Il sert à la sous-commande agent
// comme au serveur et au mode autonome qui collectent leur propre cluster.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/model"
	"github.com/ThomasSamson/wardpod-agent/scanner"
	appsv1 "k8s.io/api/apps/v1"
	authzv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// ValidateCollect vérifie la configuration nécessaire à la collecte.
func ValidateCollect(c config.Collect) error {
	var errs []error
	if c.Cluster == "" {
		errs = append(errs, errors.New("collect.cluster : nom de cluster manquant"))
	} else if err := model.ValidClusterName(c.Cluster); err != nil {
		errs = append(errs, fmt.Errorf("collect.cluster : %w", err))
	}
	if c.Interval <= 0 {
		errs = append(errs, fmt.Errorf("collect.interval invalide : %s", c.Interval))
	}
	if c.Debounce < 0 {
		errs = append(errs, fmt.Errorf("collect.debounce invalide : %s", c.Debounce))
	}
	if c.SyncTimeout <= 0 {
		errs = append(errs, fmt.Errorf("collect.syncTimeout invalide : %s", c.SyncTimeout))
	}
	if c.RetryInterval <= 0 {
		errs = append(errs, fmt.Errorf("collect.retryInterval invalide : %s", c.RetryInterval))
	}
	if c.Inventory && c.SBOMBatch < 1 {
		errs = append(errs, fmt.Errorf("collect.sbomBatch invalide : %d (au moins 1)", c.SBOMBatch))
	}
	if c.APITimeout <= 0 {
		errs = append(errs, fmt.Errorf("collect.apiTimeout invalide : %s", c.APITimeout))
	}
	for _, a := range c.InternalLoadBalancerAnnotations {
		if k, _, ok := strings.Cut(a, "="); !ok || strings.TrimSpace(k) == "" {
			errs = append(errs, fmt.Errorf("collect.internalLoadBalancerAnnotations : %q n'est pas de la forme clé=valeur", a))
		}
	}
	for _, g := range c.InternalGateways {
		if ns, name, ok := strings.Cut(g, "/"); !ok || ns == "" || name == "" || strings.Contains(name, "/") {
			errs = append(errs, fmt.Errorf("collect.internalGateways : %q n'est pas de la forme namespace/nom", g))
		}
	}
	switch c.Source {
	case "auto":
		if c.SourceCheckInterval <= 0 {
			errs = append(errs, fmt.Errorf("collect.sourceCheckInterval invalide : %s", c.SourceCheckInterval))
		}
	case model.SourceOperator, model.SourceBuiltin:
	default:
		errs = append(errs, fmt.Errorf("collect.source invalide : %q (auto, operator ou builtin)", c.Source))
	}
	return errors.Join(errs...)
}

// ValidateSources vérifie la collecte et, si le scanner intégré peut
// servir, sa configuration.
func ValidateSources(c config.Collect, s config.Scanner) error {
	err := ValidateCollect(c)
	if c.Source != model.SourceOperator {
		err = errors.Join(err, scanner.Validate(s))
	}
	if s.ServerMatch && !c.Inventory {
		// Les SBOM complets partent avec ceux de l'inventaire.
		err = errors.Join(err, errors.New("scanner.serverMatch exige collect.inventory"))
	}
	return err
}

// RestConfig renvoie la configuration d'accès à l'API Kubernetes : celle du
// contexte demandé, sinon la configuration in-cluster. Hors du cluster, le
// contexte doit être explicite : le contexte courant d'un poste pointe
// souvent vers un autre cluster que celui visé.
func RestConfig(kubeContext string, timeout time.Duration, userAgent string) (*rest.Config, error) {
	var rc *rest.Config
	var err error
	if kubeContext != "" {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		rc, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: kubeContext}).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("contexte %q : %w", kubeContext, err)
		}
	} else {
		rc, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("hors du cluster, préciser le contexte du kubeconfig (collect.kubeContext) : %w", err)
		}
	}
	rc.UserAgent = userAgent
	// Borne les requêtes de découverte et de vérification des droits ; les
	// watch des informers n'en dépendent pas.
	rc.Timeout = timeout
	return rc, nil
}

var (
	// routeKinds liste les routes qui publient un Service. Pour chaque
	// ressource, les versions sont essayées dans l'ordre et seule la première
	// servie est observée.
	routeKinds = []routeKind{
		// Gateway API : toutes partagent spec.rules[].backendRefs[].
		{gateway, "gateway.networking.k8s.io", "httproutes", []string{"v1", "v1beta1"}},
		{gateway, "gateway.networking.k8s.io", "grpcroutes", []string{"v1", "v1alpha2"}},
		{gateway, "gateway.networking.k8s.io", "tlsroutes", []string{"v1", "v1alpha3", "v1alpha2"}},
		{gateway, "gateway.networking.k8s.io", "tcproutes", []string{"v1alpha2"}},
		{gateway, "gateway.networking.k8s.io", "udproutes", []string{"v1alpha2"}},
		// Les Gateways elles-mêmes : leur classe et leurs annotations disent
		// si les routes qui s'y rattachent restent sur le réseau privé.
		{gatewayDef, "gateway.networking.k8s.io", "gateways", []string{"v1", "v1beta1"}},
		// Traefik : spec.routes[].services[]. Les deux groupes coexistent
		// pendant une migration de Traefik v2 vers v3.
		{traefik, "traefik.io", "ingressroutes", []string{"v1alpha1"}},
		{traefik, "traefik.io", "ingressroutetcps", []string{"v1alpha1"}},
		{traefik, "traefik.io", "ingressrouteudps", []string{"v1alpha1"}},
		{traefik, "traefik.containo.us", "ingressroutes", []string{"v1alpha1"}},
		{traefik, "traefik.containo.us", "ingressroutetcps", []string{"v1alpha1"}},
		{traefik, "traefik.containo.us", "ingressrouteudps", []string{"v1alpha1"}},
	}

	// contextResources sont les ressources lues pour décrire les workloads.
	contextResources = []GroupResource{
		{"apps", "replicasets"}, {"apps", "daemonsets"}, {"apps", "statefulsets"},
		{"batch", "jobs"}, {"batch", "cronjobs"},
		{"", "replicationcontrollers"}, {"", "pods"}, {"", "services"},
		{"networking.k8s.io", "ingresses"},
	}
)

// GroupResource désigne une ressource de l'API, sans version.
type GroupResource struct{ Group, Resource string }

func (g GroupResource) String() string {
	if g.Group == "" {
		return g.Resource
	}
	return g.Resource + "." + g.Group
}

type routeStyle int

const (
	gateway routeStyle = iota
	traefik
	gatewayDef // une Gateway, pas une route
)

type routeKind struct {
	style    routeStyle
	group    string
	resource string
	versions []string
}

type routeInformer struct {
	gvr    schema.GroupVersionResource
	style  routeStyle
	lister cache.GenericLister
	synced cache.InformerSynced
}

// Collector observe un cluster et construit ses snapshots.
type Collector struct {
	cfg     config.Collect
	version string
	source  Source
	kube    kubernetes.Interface
	dyn     dynamic.Interface
	typed   informers.SharedInformerFactory
	dynf    dynamicinformer.DynamicSharedInformerFactory
	listers struct {
		rs  func() []*appsv1.ReplicaSet
		rc  func() []*corev1.ReplicationController
		ds  func() []*appsv1.DaemonSet
		sts func() []*appsv1.StatefulSet
		job func() []*batchv1.Job
		cj  func() []*batchv1.CronJob
		pod func() []*corev1.Pod
		svc func() []*corev1.Service
	}
	routes    map[string]*routeInformer // par resource.group
	ingresses func() ([]*unstructuredIngress, error)
	// inv garde l'inventaire des images (nil si désactivé ou si la source
	// ne fournit pas de SBOM).
	inv     *inventory
	changed chan struct{}
	ready   atomic.Bool
}

// NewCollector prépare la collecte ; Start lance les informers.
func NewCollector(cfg config.Collect, version string, rc *rest.Config, source Source) (*Collector, error) {
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	return &Collector{
		cfg:     cfg,
		version: version,
		source:  source,
		kube:    kube,
		dyn:     dyn,
		typed:   informers.NewSharedInformerFactoryWithOptions(kube, 0, informers.WithTransform(stripManagedFields)),
		dynf:    dynamicinformer.NewDynamicSharedInformerFactory(dyn, 0),
		routes:  map[string]*routeInformer{},
		changed: make(chan struct{}, 1),
	}, nil
}

// stripManagedFields allège les objets gardés en cache : les managedFields
// représentent souvent l'essentiel de leur taille et ne servent pas ici.
func stripManagedFields(obj any) (any, error) {
	if m, err := meta.Accessor(obj); err == nil {
		m.SetManagedFields(nil)
	}
	return obj, nil
}

// served indique si l'API expose la ressource (CRD installée).
func (c *Collector) served(gvr schema.GroupVersionResource) (bool, error) {
	list, err := c.kube.Discovery().ServerResourcesForGroupVersion(gvr.GroupVersion().String())
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	for _, r := range list.APIResources {
		if r.Name == gvr.Resource {
			return true, nil
		}
	}
	return false, nil
}

// allowed vérifie que le compte de l'agent peut lister et observer la
// ressource : sans ces droits, l'informer réessaie indéfiniment.
func (c *Collector) allowed(ctx context.Context, gr GroupResource) error {
	for _, verb := range []string{"list", "watch"} {
		review := &authzv1.SelfSubjectAccessReview{Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{Group: gr.Group, Resource: gr.Resource, Verb: verb},
		}}
		res, err := c.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("vérification des droits sur %s : %w", gr, err)
		}
		if !res.Status.Allowed {
			return fmt.Errorf("droit %q manquant sur %s", verb, gr)
		}
	}
	return nil
}

// notify signale un changement susceptible de modifier le snapshot.
func (c *Collector) notify() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

// Changed reçoit un signal à chaque changement signalé par la source.
func (c *Collector) Changed() <-chan struct{} { return c.changed }

// Ready indique que les caches sont synchronisés.
func (c *Collector) Ready() bool { return c.ready.Load() }

// Start vérifie les droits, lance les informers et attend leur
// synchronisation, dans la limite de collect.syncTimeout.
func (c *Collector) Start(ctx context.Context) error {
	if err := c.source.Check(ctx, c); err != nil {
		return err
	}
	var errs []error
	for _, gr := range append(c.source.Required(), contextResources...) {
		if err := c.allowed(ctx, gr); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}

	// Créer les listers avant Start enregistre les informers dans la factory.
	t := c.typed
	rsL, rcL := t.Apps().V1().ReplicaSets().Lister(), t.Core().V1().ReplicationControllers().Lister()
	dsL, stsL := t.Apps().V1().DaemonSets().Lister(), t.Apps().V1().StatefulSets().Lister()
	jobL, cjL := t.Batch().V1().Jobs().Lister(), t.Batch().V1().CronJobs().Lister()
	podL, svcL, ingL := t.Core().V1().Pods().Lister(), t.Core().V1().Services().Lister(), t.Networking().V1().Ingresses().Lister()
	all := labels.Everything()
	c.listers.rs = func() []*appsv1.ReplicaSet { l, _ := rsL.List(all); return l }
	c.listers.rc = func() []*corev1.ReplicationController { l, _ := rcL.List(all); return l }
	c.listers.ds = func() []*appsv1.DaemonSet { l, _ := dsL.List(all); return l }
	c.listers.sts = func() []*appsv1.StatefulSet { l, _ := stsL.List(all); return l }
	c.listers.job = func() []*batchv1.Job { l, _ := jobL.List(all); return l }
	c.listers.cj = func() []*batchv1.CronJob { l, _ := cjL.List(all); return l }
	c.listers.pod = func() []*corev1.Pod { l, _ := podL.List(all); return l }
	c.listers.svc = func() []*corev1.Service { l, _ := svcL.List(all); return l }
	c.ingresses = func() ([]*unstructuredIngress, error) {
		l, err := ingL.List(all)
		out := make([]*unstructuredIngress, 0, len(l))
		for _, i := range l {
			u := &unstructuredIngress{Namespace: i.Namespace, Name: i.Name}
			if b := i.Spec.DefaultBackend; b != nil && b.Service != nil {
				u.Services = append(u.Services, b.Service.Name)
			}
			for _, r := range i.Spec.Rules {
				if r.HTTP == nil {
					continue
				}
				for _, p := range r.HTTP.Paths {
					if p.Backend.Service != nil {
						u.Services = append(u.Services, p.Backend.Service.Name)
					}
				}
			}
			out = append(out, u)
		}
		return out, err
	}
	if err := c.source.Register(c); err != nil {
		return err
	}

	t.Start(ctx.Done())
	c.dynf.Start(ctx.Done())
	slog.Info("synchronisation des caches", "source", c.source.Name())
	syncCtx, cancel := context.WithTimeout(ctx, c.cfg.SyncTimeout)
	defer cancel()
	for typ, ok := range t.WaitForCacheSync(syncCtx.Done()) {
		if !ok {
			return fmt.Errorf("cache %v non synchronisé après %s", typ, c.cfg.SyncTimeout)
		}
	}
	for gvr, ok := range c.dynf.WaitForCacheSync(syncCtx.Done()) {
		if !ok {
			return fmt.Errorf("cache %v non synchronisé après %s", gvr, c.cfg.SyncTimeout)
		}
	}
	cancel()
	c.RefreshRoutes(ctx)
	c.startInventory(ctx)
	c.ready.Store(true)
	slog.Info("caches synchronisés", "routes", len(c.routes))
	return nil
}

// dynamicInformer enregistre un informer dynamique allégé.
func (c *Collector) dynamicInformer(gvr schema.GroupVersionResource) cache.SharedIndexInformer {
	inf := c.dynf.ForResource(gvr).Informer()
	_ = inf.SetTransform(stripManagedFields)
	return inf
}

// RefreshRoutes observe les types de routes servis par l'API. Elle est
// rappelée avant chaque envoi : une CRD installée après le démarrage, ou une
// découverte en échec passager, est ainsi prise en compte.
func (c *Collector) RefreshRoutes(ctx context.Context) {
	var started []*routeInformer
	for _, rk := range routeKinds {
		key := rk.resource + "." + rk.group
		if _, ok := c.routes[key]; ok {
			continue
		}
		for _, v := range rk.versions {
			gvr := schema.GroupVersionResource{Group: rk.group, Version: v, Resource: rk.resource}
			ok, err := c.served(gvr)
			if err != nil {
				slog.Warn("découverte d'un type de route", "resource", gvr.String(), "err", err)
				break
			}
			if !ok {
				continue
			}
			if err := c.allowed(ctx, GroupResource{rk.group, rk.resource}); err != nil {
				slog.Warn("type de route ignoré : l'exposition des workloads qu'il publie sera sous-estimée", "err", err)
				break
			}
			inf := c.dynamicInformer(gvr)
			ri := &routeInformer{gvr: gvr, style: rk.style, lister: cache.NewGenericLister(inf.GetIndexer(), gvr.GroupResource()), synced: inf.HasSynced}
			c.routes[key] = ri
			started = append(started, ri)
			break
		}
	}
	if len(started) == 0 {
		return
	}
	c.dynf.Start(ctx.Done())
	syncCtx, cancel := context.WithTimeout(ctx, c.cfg.SyncTimeout)
	defer cancel()
	for _, ri := range started {
		if cache.WaitForCacheSync(syncCtx.Done(), ri.synced) {
			slog.Info("type de route observé", "resource", ri.gvr.String())
		} else {
			slog.Warn("type de route non synchronisé : ignoré tant qu'il ne l'est pas", "resource", ri.gvr.String())
		}
	}
}

type unstructuredIngress struct {
	Namespace, Name string
	Services        []string
}

type workloadKey struct{ Namespace, Kind, Name string }

type podTemplate struct {
	labels    map[string]string
	spec      *corev1.PodSpec
	running   bool
	ownerKind string
	ownerName string
}

func controller(refs []metav1.OwnerReference) (string, string) {
	for _, r := range refs {
		if r.Controller != nil && *r.Controller {
			return r.Kind, r.Name
		}
	}
	return "", ""
}

// builtInControllers sont les contrôleurs auxquels le Trivy Operator rattache
// ses rapports. Un pod géré par un autre contrôleur (pod statique géré par
// un Node, opérateur tiers…) est rapporté comme Pod.
var builtInControllers = map[string]bool{
	"ReplicaSet": true, "ReplicationController": true, "StatefulSet": true, "DaemonSet": true, "Job": true,
}

// templates indexe le pod template de chaque contrôleur susceptible d'être
// cité par un rapport Trivy.
func (c *Collector) templates() map[workloadKey]podTemplate {
	m := map[workloadKey]podTemplate{}
	for _, o := range c.listers.rs() {
		k, n := controller(o.OwnerReferences)
		m[workloadKey{o.Namespace, "ReplicaSet", o.Name}] = podTemplate{o.Spec.Template.Labels, &o.Spec.Template.Spec, o.Status.Replicas > 0, k, n}
	}
	for _, o := range c.listers.rc() {
		if o.Spec.Template == nil {
			continue
		}
		k, n := controller(o.OwnerReferences)
		m[workloadKey{o.Namespace, "ReplicationController", o.Name}] = podTemplate{o.Spec.Template.Labels, &o.Spec.Template.Spec, o.Status.Replicas > 0, k, n}
	}
	for _, o := range c.listers.ds() {
		m[workloadKey{o.Namespace, "DaemonSet", o.Name}] = podTemplate{o.Spec.Template.Labels, &o.Spec.Template.Spec, o.Status.CurrentNumberScheduled > 0, "", ""}
	}
	for _, o := range c.listers.sts() {
		m[workloadKey{o.Namespace, "StatefulSet", o.Name}] = podTemplate{o.Spec.Template.Labels, &o.Spec.Template.Spec, o.Status.Replicas > 0, "", ""}
	}
	for _, o := range c.listers.job() {
		k, n := controller(o.OwnerReferences)
		m[workloadKey{o.Namespace, "Job", o.Name}] = podTemplate{o.Spec.Template.Labels, &o.Spec.Template.Spec, o.Status.Active > 0, k, n}
	}
	for _, o := range c.listers.cj() {
		t := o.Spec.JobTemplate.Spec.Template
		suspended := o.Spec.Suspend != nil && *o.Spec.Suspend
		m[workloadKey{o.Namespace, "CronJob", o.Name}] = podTemplate{t.Labels, &t.Spec, !suspended, "", ""}
	}
	for _, o := range c.listers.pod() {
		k, n := controller(o.OwnerReferences)
		if builtInControllers[k] {
			continue // couvert par son contrôleur
		}
		running := o.Status.Phase == corev1.PodRunning || o.Status.Phase == corev1.PodPending
		m[workloadKey{o.Namespace, "Pod", o.Name}] = podTemplate{o.Labels, &o.Spec, running, k, n}
	}
	return m
}

func (c *Collector) entrypoints(policy exposurePolicy) entrypoints {
	eps := entrypoints{}
	if ings, err := c.ingresses(); err == nil {
		for _, i := range ings {
			for _, s := range i.Services {
				eps.add(i.Namespace, s, "Ingress/"+i.Name, false)
			}
		}
	}
	list := func(ri *routeInformer) []*unstructured.Unstructured {
		if !ri.synced() {
			return nil
		}
		objs, _ := ri.lister.List(labels.Everything())
		out := make([]*unstructured.Unstructured, 0, len(objs))
		for _, o := range objs {
			if u, ok := o.(*unstructured.Unstructured); ok {
				out = append(out, u)
			}
		}
		return out
	}
	internalGws := map[string]bool{}
	for _, ri := range c.routes {
		if ri.style == gatewayDef {
			for _, u := range list(ri) {
				if gatewayInternal(u, policy) {
					internalGws[u.GetNamespace()+"/"+u.GetName()] = true
				}
			}
		}
	}
	for _, ri := range c.routes {
		if ri.style == gatewayDef {
			continue
		}
		for _, u := range list(ri) {
			addRouteBackends(eps, ri.style, u, ri.style == gateway && routeInternal(u, internalGws, policy))
		}
	}
	return eps
}

// gatewayInternal applique la politique d'exposition à une Gateway.
func gatewayInternal(u *unstructured.Unstructured, policy exposurePolicy) bool {
	class, _, _ := unstructured.NestedString(u.Object, "spec", "gatewayClassName")
	ann, _, _ := unstructured.NestedStringMap(u.Object, "spec", "infrastructure", "annotations")
	return policy.internalGateway(u.GetNamespace(), u.GetName(), class, ann)
}

// routeInternal dit si une route Gateway API reste sur le réseau privé :
// tous ses parents sont des Gateways internes, ou des Services (maillage,
// trafic est-ouest). Un parent inconnu, ou l'absence de parent, la laisse
// exposée.
func routeInternal(u *unstructured.Unstructured, internalGws map[string]bool, policy exposurePolicy) bool {
	parents, _, _ := unstructured.NestedSlice(u.Object, "spec", "parentRefs")
	if len(parents) == 0 {
		return false
	}
	for _, p := range parents {
		ref := asMap(p)
		kind, _ := ref["kind"].(string)
		group, hasGroup := ref["group"].(string)
		name, _ := ref["name"].(string)
		ns, _ := ref["namespace"].(string)
		if ns == "" {
			ns = u.GetNamespace()
		}
		switch {
		case kind == "Service" && hasGroup && (group == "" || group == "core"):
		case (kind == "" || kind == "Gateway") && (!hasGroup || group == "gateway.networking.k8s.io"):
			if key := ns + "/" + name; !internalGws[key] && !policy.gateways[key] {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func addRouteBackends(eps entrypoints, style routeStyle, u *unstructured.Unstructured, internal bool) {
	switch style {
	case gateway:
		rules, _, _ := unstructured.NestedSlice(u.Object, "spec", "rules")
		for _, r := range rules {
			refs, _, _ := unstructured.NestedSlice(asMap(r), "backendRefs")
			for _, ref := range refs {
				addBackend(eps, u, asMap(ref), internal)
			}
		}
	case traefik:
		routes, _, _ := unstructured.NestedSlice(u.Object, "spec", "routes")
		for _, r := range routes {
			svcs, _, _ := unstructured.NestedSlice(asMap(r), "services")
			for _, s := range svcs {
				addBackend(eps, u, asMap(s), internal)
			}
		}
	}
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func addBackend(eps entrypoints, route *unstructured.Unstructured, ref map[string]any, internal bool) {
	if kind, _ := ref["kind"].(string); kind != "" && kind != "Service" {
		return
	}
	name, _ := ref["name"].(string)
	if name == "" {
		return
	}
	ns, _ := ref["namespace"].(string)
	if ns == "" {
		ns = route.GetNamespace()
	}
	eps.add(ns, name, route.GetKind()+"/"+route.GetName(), internal)
}

var hostname, _ = os.Hostname()

// Snapshot construit l'état complet du cluster.
func (c *Collector) Snapshot() (*model.Snapshot, error) {
	reports, err := c.source.Reports()
	if err != nil {
		return nil, err
	}
	tpls := c.templates()
	services := c.listers.svc()
	policy := newExposurePolicy(c.cfg)
	eps := c.entrypoints(policy)

	var unscanned []string
	if u, ok := c.source.(interface{ Unscanned() []string }); ok {
		unscanned = u.Unscanned()
	}
	var inventory []model.ImageSBOM
	var sboms []model.SBOM
	if c.inv != nil {
		c.inv.update(c.source.(sbomLoader).sbomRefs(reports))
		// Les SBOM demandés partent ensuite par lots (SBOMUpload), sauf en
		// mode -dump, où le snapshot est la seule sortie.
		inventory = c.inv.declared()
		if c.inv.dumping() {
			sboms = c.inv.sboms(0)
		}
	}
	serverMatch := false
	if d, ok := c.source.(documentSource); ok {
		serverMatch = d.ServerMatch()
	}
	snap := &model.Snapshot{
		Source:       c.source.Name(),
		ServerMatch:  serverMatch,
		Unscanned:    unscanned,
		Inventory:    inventory,
		SBOMs:        sboms,
		Version:      model.SnapshotVersion,
		Cluster:      c.cfg.Cluster,
		Environment:  c.cfg.Environment,
		AgentVersion: c.version,
		// Nom du pod : deux agents qui partagent un jeton sont repérés.
		AgentInstance: hostname,
		CollectedAt:   time.Now().UTC(),
		Workloads:     []model.Workload{},
		Reports:       make([]model.VulnerabilityReport, 0, len(reports)),
	}
	workloads := map[workloadKey]*model.Workload{}
	for _, r := range reports {
		snap.Reports = append(snap.Reports, r.Report)
		key := r.Workload
		if workloads[key] != nil {
			continue
		}
		w := &model.Workload{Namespace: key.Namespace, Kind: key.Kind, Name: key.Name, Exposure: model.ExposureNone, Containers: []model.Container{}}
		if tpl, ok := tpls[key]; ok {
			w.Running = tpl.running
			w.OwnerKind, w.OwnerName = tpl.ownerKind, tpl.ownerName
			w.Exposure, w.ExposedVia = resolveExposure(key.Namespace, tpl.labels, tpl.spec, services, eps, policy)
			for i := range tpl.spec.InitContainers {
				ct := &tpl.spec.InitContainers[i]
				w.Containers = append(w.Containers, model.Container{Name: ct.Name, Image: ct.Image, Security: securityFor(tpl.spec, ct)})
			}
			for i := range tpl.spec.Containers {
				ct := &tpl.spec.Containers[i]
				w.Containers = append(w.Containers, model.Container{Name: ct.Name, Image: ct.Image, Security: securityFor(tpl.spec, ct)})
			}
		}
		workloads[key] = w
	}

	for _, w := range workloads {
		snap.Workloads = append(snap.Workloads, *w)
	}
	sort.Slice(snap.Workloads, func(i, j int) bool {
		a, b := snap.Workloads[i], snap.Workloads[j]
		return a.Namespace+"/"+a.Kind+"/"+a.Name < b.Namespace+"/"+b.Kind+"/"+b.Name
	})
	// Un champ hostile (image choisie par un utilisateur du cluster) ferait
	// refuser tout le snapshot par le serveur.
	if n := snap.DropInvalidVulnerabilities(); n > 0 {
		slog.Warn("vulnérabilités invalides écartées", "count", n)
	}
	return snap, nil
}
