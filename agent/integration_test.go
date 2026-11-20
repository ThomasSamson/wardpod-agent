package agent

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Ces tests démarrent un vrai kube-apiserver (envtest). Ils sont ignorés si
// KUBEBUILDER_ASSETS n'est pas défini : voir `make test-integration`.

func crd(group, version, kind, plural string, namespaced bool) *apiextv1.CustomResourceDefinition {
	scope := apiextv1.ClusterScoped
	if namespaced {
		scope = apiextv1.NamespaceScoped
	}
	preserve := true
	var annotations map[string]string
	if strings.HasSuffix(group, ".k8s.io") {
		// Les groupes *.k8s.io sont protégés : la vraie CRD porte cette
		// annotation.
		annotations = map[string]string{"api-approved.kubernetes.io": "https://github.com/kubernetes-sigs/gateway-api/pull/1"}
	}
	return &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: plural + "." + group, Annotations: annotations},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: group,
			Names: apiextv1.CustomResourceDefinitionNames{Kind: kind, ListKind: kind + "List", Plural: plural, Singular: strings.ToLower(kind)},
			Scope: scope,
			Versions: []apiextv1.CustomResourceDefinitionVersion{{
				Name: version, Served: true, Storage: true,
				Schema: &apiextv1.CustomResourceValidation{OpenAPIV3Schema: &apiextv1.JSONSchemaProps{Type: "object", XPreserveUnknownFields: &preserve}},
			}},
		},
	}
}

var (
	vulnCRD      = crd("aquasecurity.github.io", "v1alpha1", "VulnerabilityReport", "vulnerabilityreports", true)
	httpRouteCRD = crd("gateway.networking.k8s.io", "v1", "HTTPRoute", "httproutes", true)
	tcpRouteCRD  = crd("traefik.io", "v1alpha1", "IngressRouteTCP", "ingressroutetcps", true)
)

func startEnv(t *testing.T, crds ...*apiextv1.CustomResourceDefinition) (*envtest.Environment, *rest.Config) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("REQUIRE_ENVTEST") != "" {
			t.Fatal("REQUIRE_ENVTEST défini mais KUBEBUILDER_ASSETS vide")
		}
		t.Skip("KUBEBUILDER_ASSETS non défini : test d'intégration ignoré")
	}
	env := &envtest.Environment{CRDs: crds}
	rc, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	return env, rc
}

// mustCreate arrête le test (par panique) si la création a échoué.
func mustCreate[T any](obj T, err error) T {
	if err != nil {
		panic(err)
	}
	return obj
}

func vulnReport(ns, name, kind, workload, container string, ids ...string) *unstructured.Unstructured {
	var vulns []any
	for _, id := range ids {
		vulns = append(vulns, map[string]any{"vulnerabilityID": id, "resource": "openssl", "installedVersion": "3.0.0", "fixedVersion": "3.0.9", "severity": "CRITICAL", "score": 9.8})
	}
	u := report(name, map[string]string{lblKind: kind, lblName: workload, lblNamespace: ns, lblContainer: container}, nil, vulns)
	u.SetAPIVersion("aquasecurity.github.io/v1alpha1")
	u.SetKind("VulnerabilityReport")
	u.SetNamespace(ns)
	return u
}

func TestIntegrationCollector(t *testing.T) {
	_, rc := startEnv(t, vulnCRD, httpRouteCRD)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kube := kubernetes.NewForConfigOrDie(rc)
	dyn := dynamic.NewForConfigOrDie(rc)

	ns := "app"
	mustCreate(kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}))

	// Un ReplicaSet géré par un Deployment, publié par un Service et une
	// HTTPRoute.
	labels := map[string]string{"app": "web", "pod-template-hash": "abc"}
	rs := mustCreate(kube.AppsV1().ReplicaSets(ns).Create(ctx, &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "web-abc", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: types.UID("u1"), Controller: boolp(true)}}},
		Spec: appsv1.ReplicaSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "web", Image: "nginx:1.27",
					SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"CAP_NET_ADMIN"}}},
				}}},
			},
		},
	}, metav1.CreateOptions{}))
	rs.Status.Replicas = 2
	mustCreate(kube.AppsV1().ReplicaSets(ns).UpdateStatus(ctx, rs, metav1.UpdateOptions{}))
	mustCreate(kube.CoreV1().Services(ns).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}, Ports: []corev1.ServicePort{{Port: 80}}},
	}, metav1.CreateOptions{}))
	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]any{"name": "web", "namespace": ns},
		"spec":     map[string]any{"rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": "web", "port": int64(80)}}}}},
	}}
	mustCreate(dyn.Resource(schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}).Namespace(ns).Create(ctx, route, metav1.CreateOptions{}))

	// Un pod statique (contrôleur Node) en hostNetwork, et un Ingress.
	pod := mustCreate(kube.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-node1", OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Node", Name: "node1", UID: types.UID("n1"), Controller: boolp(true)}}},
		Spec:       corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "etcd", Image: "etcd:3.5"}}},
	}, metav1.CreateOptions{}))
	pod.Status.Phase = corev1.PodRunning
	mustCreate(kube.CoreV1().Pods(ns).UpdateStatus(ctx, pod, metav1.UpdateOptions{}))
	mustCreate(kube.NetworkingV1().Ingresses(ns).Create(ctx, &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "rien"},
		Spec:       networkingv1.IngressSpec{DefaultBackend: &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "absent", Port: networkingv1.ServiceBackendPort{Number: 80}}}},
	}, metav1.CreateOptions{}))

	reports := dyn.Resource(gvrVulnReports).Namespace(ns)
	mustCreate(reports.Create(ctx, vulnReport(ns, "replicaset-web-abc-web", "ReplicaSet", "web-abc", "web", "CVE-2026-0001"), metav1.CreateOptions{}))
	mustCreate(reports.Create(ctx, vulnReport(ns, "pod-etcd-node1-etcd", "Pod", "etcd-node1", "etcd", "CVE-2026-0002"), metav1.CreateOptions{}))

	cfg := config.Collect{Cluster: "it", Interval: time.Minute, Debounce: 200 * time.Millisecond, SyncTimeout: 30 * time.Second}
	c, err := NewCollector(cfg, "test", rc, &OperatorSource{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !c.Ready() {
		t.Fatal("collecteur non prêt après Start")
	}
	snap, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Reports) != 2 || len(snap.Workloads) != 2 {
		t.Fatalf("2 rapports et 2 workloads attendus : %+v", snap)
	}
	byName := map[string]model.Workload{}
	for _, w := range snap.Workloads {
		byName[w.Name] = w
	}
	web := byName["web-abc"]
	if !web.Running || web.OwnerKind != "Deployment" || web.Exposure != model.ExposureInternet || !slices.Equal(web.ExposedVia, []string{"HTTPRoute/web"}) {
		t.Errorf("ReplicaSet mal décrit : %+v", web)
	}
	if len(web.Containers) != 1 || !slices.Equal(web.Containers[0].Security.DangerousCaps, []string{"NET_ADMIN"}) {
		t.Errorf("securityContext mal lu : %+v", web.Containers)
	}
	etcd := byName["etcd-node1"]
	if !etcd.Running || etcd.OwnerKind != "Node" || etcd.Exposure != model.ExposureInternet || !etcd.Containers[0].Security.HostNamespaces {
		t.Errorf("pod statique mal décrit : %+v", etcd)
	}

	// Boucle d'envoi : un nouveau rapport déclenche un envoi après le calme.
	dest := &captureDest{ch: make(chan *model.Snapshot, 10)}
	loop := &Loop{Collector: c, Destination: dest, Interval: time.Minute, Debounce: 200 * time.Millisecond}
	go loop.Run(ctx)
	first := dest.next(t)
	if len(first.Reports) != 2 {
		t.Fatalf("premier envoi : %d rapports", len(first.Reports))
	}
	mustCreate(reports.Create(ctx, vulnReport(ns, "pod-etcd-node1-etcd-2", "Pod", "etcd-node1", "etcd", "CVE-2026-0003"), metav1.CreateOptions{}))
	if second := dest.next(t); len(second.Reports) != 3 {
		t.Fatalf("envoi après changement : %d rapports", len(second.Reports))
	}
	if loop.LastSuccess().IsZero() {
		t.Fatal("dernier envoi réussi non enregistré")
	}
}

type captureDest struct{ ch chan *model.Snapshot }

func (d *captureDest) Send(_ context.Context, s *model.Snapshot) (model.IngestReply, error) {
	d.ch <- s
	return model.IngestReply{}, nil
}

func (d *captureDest) SendSBOMs(context.Context, *model.SBOMUpload) (model.SBOMReply, error) {
	return model.SBOMReply{}, nil
}

func (d *captureDest) next(t *testing.T) *model.Snapshot {
	t.Helper()
	select {
	case s := <-d.ch:
		return s
	case <-time.After(20 * time.Second):
		t.Fatal("aucun snapshot envoyé")
		return nil
	}
}

// within attend un snapshot pendant d au plus ; faux si aucun n'arrive.
func (d *captureDest) within(wait time.Duration) (*model.Snapshot, bool) {
	select {
	case s := <-d.ch:
		return s, true
	case <-time.After(wait):
		return nil, false
	}
}

func TestIntegrationMissingCRD(t *testing.T) {
	_, rc := startEnv(t)
	c, err := NewCollector(config.Collect{Cluster: "it", SyncTimeout: 10 * time.Second}, "test", rc, &OperatorSource{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "Trivy Operator") {
		t.Fatalf("erreur « CRD absente » attendue, obtenu %v", err)
	}
}

func TestIntegrationMissingRBAC(t *testing.T) {
	env, _ := startEnv(t, vulnCRD)
	user, err := env.AddUser(envtest.User{Name: "sans-droits"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCollector(config.Collect{Cluster: "it", SyncTimeout: 10 * time.Second}, "test", user.Config(), &OperatorSource{})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), `droit "list" manquant sur vulnerabilityreports.aquasecurity.github.io`) || !strings.Contains(err.Error(), "pods") {
		t.Fatalf("erreur de droits attendue, obtenu %v", err)
	}
}

func TestIntegrationRouteInstalledLater(t *testing.T) {
	env, rc := startEnv(t, vulnCRD)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := NewCollector(config.Collect{Cluster: "it", SyncTimeout: 20 * time.Second}, "test", rc, &OperatorSource{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if len(c.routes) != 0 {
		t.Fatalf("aucun type de route attendu : %v", c.routes)
	}
	if _, err := envtest.InstallCRDs(env.Config, envtest.CRDInstallOptions{CRDs: []*apiextv1.CustomResourceDefinition{tcpRouteCRD}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		c.RefreshRoutes(ctx)
		_, ok := c.routes["ingressroutetcps.traefik.io"]
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("type de route installé après le démarrage non détecté")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
