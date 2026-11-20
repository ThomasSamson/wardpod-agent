package agent

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/model"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func validAgent() config.Agent {
	return config.Agent{ServerURL: "https://wardpod.example.org", Token: "jeton-factice", HTTPTimeout: time.Minute}
}

func validCollect() config.Collect {
	return config.Collect{Cluster: "test", Interval: time.Minute, Debounce: 10 * time.Second, SyncTimeout: time.Minute, APITimeout: 10 * time.Second, RetryInterval: 5 * time.Second, Source: "auto", SourceCheckInterval: time.Minute}
}

func TestValidateCollect(t *testing.T) {
	if err := ValidateCollect(validCollect()); err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	for name, mutate := range map[string]func(*config.Collect){
		"cluster manquant":             func(c *config.Collect) { c.Cluster = "" },
		"intervalle nul":               func(c *config.Collect) { c.Interval = 0 },
		"debounce négatif":             func(c *config.Collect) { c.Debounce = -time.Second },
		"délai de synchronisation nul": func(c *config.Collect) { c.SyncTimeout = 0 },
		"source inconnue":              func(c *config.Collect) { c.Source = "trivy" },
		"réévaluation nulle":           func(c *config.Collect) { c.SourceCheckInterval = 0 },
	} {
		c := validCollect()
		mutate(&c)
		if ValidateCollect(c) == nil {
			t.Errorf("%s : configuration invalide acceptée", name)
		}
	}
	// Le scanner n'est validé que s'il peut servir.
	sc := config.Default().Scanner
	sc.Concurrency = 0
	c := validCollect()
	if ValidateSources(c, sc) == nil {
		t.Error("scanner invalide accepté en mode auto")
	}
	c.Source = "operator"
	if err := ValidateSources(c, sc); err != nil {
		t.Errorf("scanner validé alors que la source est l'opérateur : %v", err)
	}
}

func TestNewHTTPDestination(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Agent)
		ok     bool
	}{
		{"https", func(*config.Agent) {}, true},
		{"http sur localhost", func(c *config.Agent) { c.ServerURL = "http://localhost:8080" }, true},
		{"http sur 127.0.0.1", func(c *config.Agent) { c.ServerURL = "http://127.0.0.1:8080" }, true},
		{"http sur ::1", func(c *config.Agent) { c.ServerURL = "http://[::1]:8080" }, true},
		{"http distant refusé", func(c *config.Agent) { c.ServerURL = "http://wardpod.svc:8080" }, false},
		{"http distant autorisé explicitement", func(c *config.Agent) { c.ServerURL = "http://wardpod.svc:8080"; c.AllowInsecure = true }, true},
		{"schéma inconnu", func(c *config.Agent) { c.ServerURL = "ftp://example.org" }, false},
		{"URL sans hôte", func(c *config.Agent) { c.ServerURL = "wardpod" }, false},
		{"jeton manquant", func(c *config.Agent) { c.Token = "" }, false},
		{"délai nul", func(c *config.Agent) { c.HTTPTimeout = 0 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validAgent()
			tt.mutate(&c)
			if _, err := NewHTTPDestination(c); (err == nil) != tt.ok {
				t.Fatalf("NewHTTPDestination() = %v, valide attendu : %v", err, tt.ok)
			}
		})
	}
}

func TestSendRefusesRedirect(t *testing.T) {
	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v1/ingest", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	cfg := validAgent()
	cfg.ServerURL = srv.URL
	d, err := NewHTTPDestination(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Send(context.Background(), &model.Snapshot{}); err == nil {
		t.Fatal("une redirection doit être une erreur")
	}
	if leaked {
		t.Fatal("la redirection a été suivie")
	}
}

// Un certificat que le système ne reconnaît pas (ici auto-signé) arrête
// l'envoi avant que le jeton ne parte.
func TestSendRefusesUntrustedCertificate(t *testing.T) {
	var reached bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer srv.Close()

	cfg := validAgent()
	cfg.ServerURL = srv.URL
	d, err := NewHTTPDestination(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Send(context.Background(), &model.Snapshot{}); err == nil {
		t.Fatal("un certificat non reconnu doit être une erreur")
	}
	if reached {
		t.Fatal("la requête a atteint un serveur au certificat non reconnu")
	}
}

func TestSendPayload(t *testing.T) {
	var got model.Snapshot
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ingest" || r.Header.Get("Authorization") != "Bearer jeton-factice" || r.Header.Get("Content-Encoding") != "gzip" {
			http.Error(w, "requête inattendue", http.StatusBadRequest)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err == nil {
			err = json.NewDecoder(zr).Decode(&got)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte(`{"findings":1,"sboms":0,"sbomsWanted":["sha256:a"]}`))
	}))
	defer srv.Close()
	cfg := validAgent()
	cfg.ServerURL = srv.URL + "/"
	d, _ := NewHTTPDestination(cfg)
	reply, err := d.Send(context.Background(), &model.Snapshot{Cluster: "c1", Version: model.SnapshotVersion})
	if err != nil {
		t.Fatal(err)
	}
	if got.Cluster != "c1" {
		t.Fatalf("snapshot reçu : %+v", got)
	}
	// La réponse demande des SBOM.
	if len(reply.SBOMsWanted) != 1 || reply.SBOMsWanted[0] != "sha256:a" {
		t.Fatalf("réponse : %+v", reply)
	}

	srvErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "jeton refusé", http.StatusUnauthorized)
	}))
	defer srvErr.Close()
	cfg.ServerURL = srvErr.URL
	d, _ = NewHTTPDestination(cfg)
	if _, err := d.Send(context.Background(), &model.Snapshot{}); err == nil || !strings.Contains(err.Error(), "jeton refusé") {
		t.Fatalf("erreur du serveur attendue, obtenu %v", err)
	}
}

func TestTemplates(t *testing.T) {
	ctrl := func(kind, name string) []metav1.OwnerReference {
		return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: boolp(true)}}
	}
	pod := func(name string, owners []metav1.OwnerReference) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, OwnerReferences: owners},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
	}
	var a Collector
	a.listers.rs = func() []*appsv1.ReplicaSet {
		return []*appsv1.ReplicaSet{{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-abc", OwnerReferences: ctrl("Deployment", "web")}, Status: appsv1.ReplicaSetStatus{Replicas: 2}}}
	}
	a.listers.rc = func() []*corev1.ReplicationController {
		return []*corev1.ReplicationController{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "legacy"}, Spec: corev1.ReplicationControllerSpec{Template: &corev1.PodTemplateSpec{}}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sans-template"}},
		}
	}
	a.listers.ds = func() []*appsv1.DaemonSet { return nil }
	a.listers.sts = func() []*appsv1.StatefulSet { return nil }
	a.listers.job = func() []*batchv1.Job { return nil }
	a.listers.cj = func() []*batchv1.CronJob { return nil }
	a.listers.pod = func() []*corev1.Pod {
		return []*corev1.Pod{
			pod("web-abc-1", ctrl("ReplicaSet", "web-abc")),
			pod("kube-apiserver-node1", ctrl("Node", "node1")),
			pod("pg-1", ctrl("Cluster", "pg")),
			pod("nu", nil),
		}
	}

	m := a.templates()
	for _, k := range []workloadKey{
		{"ns", "ReplicaSet", "web-abc"},
		{"ns", "ReplicationController", "legacy"},
		{"ns", "Pod", "kube-apiserver-node1"},
		{"ns", "Pod", "pg-1"},
		{"ns", "Pod", "nu"},
	} {
		if _, ok := m[k]; !ok {
			t.Errorf("template absent : %v", k)
		}
	}
	if _, ok := m[workloadKey{"ns", "Pod", "web-abc-1"}]; ok {
		t.Error("un pod géré par un ReplicaSet ne doit pas être indexé")
	}
	if tpl := m[workloadKey{"ns", "Pod", "pg-1"}]; !tpl.running || tpl.ownerKind != "Cluster" || tpl.ownerName != "pg" {
		t.Errorf("pod d'opérateur tiers mal décrit : %+v", tpl)
	}
	if tpl := m[workloadKey{"ns", "ReplicaSet", "web-abc"}]; tpl.ownerKind != "Deployment" || !tpl.running {
		t.Errorf("ReplicaSet mal décrit : %+v", tpl)
	}
}

func report(name string, lbls, annotations map[string]string, vulns []any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "VulnerabilityReport",
		"report": map[string]any{
			"artifact":        map[string]any{"repository": "library/nginx", "tag": "1.27", "digest": "sha256:abc"},
			"registry":        map[string]any{"server": "index.docker.io"},
			"updateTimestamp": "2026-10-01T10:00:00Z",
			"vulnerabilities": vulns,
		},
	}}
	u.SetNamespace("ns")
	u.SetName(name)
	u.SetLabels(lbls)
	u.SetAnnotations(annotations)
	return u
}

func TestReportWorkload(t *testing.T) {
	long := strings.Repeat("a", 70)
	tests := []struct {
		name string
		u    *unstructured.Unstructured
		want workloadKey
		ok   bool
	}{
		{"labels complets", report("r", map[string]string{lblKind: "ReplicaSet", lblName: "web-abc", lblNamespace: "ns"}, nil, nil), workloadKey{"ns", "ReplicaSet", "web-abc"}, true},
		{"nom long dans l'annotation", report("r", map[string]string{lblKind: "ReplicaSet", lblNamespace: "ns", lblName + "-hash": "123"}, map[string]string{lblName: long}, nil), workloadKey{"ns", "ReplicaSet", long}, true},
		{"namespace déduit du rapport", report("r", map[string]string{lblKind: "Pod", lblName: "p"}, nil, nil), workloadKey{"ns", "Pod", "p"}, true},
		{"sans labels", report("r", nil, nil, nil), workloadKey{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := reportWorkload(tt.u)
			if ok != tt.ok || (ok && got != tt.want) {
				t.Fatalf("reportWorkload = %v, %v ; attendu %v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestSnapshot(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	vulns := []any{map[string]any{"vulnerabilityID": "CVE-2026-0001", "resource": "openssl", "installedVersion": "3.0.0", "severity": "high", "score": 7.5}}
	for _, r := range []*unstructured.Unstructured{
		report("ok", map[string]string{lblKind: "Pod", lblName: "static", lblNamespace: "ns", lblContainer: "c"}, nil, vulns),
		report("sans-labels", nil, nil, vulns),
		report("vide", map[string]string{lblKind: "Pod", lblName: "vide", lblNamespace: "ns"}, nil, nil),
	} {
		if err := indexer.Add(r); err != nil {
			t.Fatal(err)
		}
	}

	var a Collector
	a.cfg = validCollect()
	a.source = &OperatorSource{lister: cache.NewGenericLister(indexer, gvrVulnReports.GroupResource())}
	a.listers.rs = func() []*appsv1.ReplicaSet { return nil }
	a.listers.rc = func() []*corev1.ReplicationController { return nil }
	a.listers.ds = func() []*appsv1.DaemonSet { return nil }
	a.listers.sts = func() []*appsv1.StatefulSet { return nil }
	a.listers.job = func() []*batchv1.Job { return nil }
	a.listers.cj = func() []*batchv1.CronJob { return nil }
	a.listers.svc = func() []*corev1.Service { return nil }
	a.listers.pod = func() []*corev1.Pod {
		return []*corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "static", OwnerReferences: []metav1.OwnerReference{{Kind: "Node", Name: "n1", Controller: boolp(true)}}},
			Spec:       corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "c", Image: "nginx"}}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}}
	}
	a.ingresses = func() ([]*unstructuredIngress, error) { return nil, nil }

	snap, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Reports) != 2 {
		t.Fatalf("2 rapports attendus (celui sans labels est ignoré), obtenu %d", len(snap.Reports))
	}
	var static *model.Workload
	for i := range snap.Workloads {
		if snap.Workloads[i].Name == "static" {
			static = &snap.Workloads[i]
		}
	}
	if static == nil || !static.Running || static.Exposure != model.ExposureInternet || len(static.Containers) != 1 || !static.Containers[0].Security.HostNamespaces {
		t.Fatalf("pod statique mal décrit : %+v", static)
	}
	for _, r := range snap.Reports {
		if r.Vulnerabilities == nil {
			t.Fatalf("liste de vulnérabilités nulle pour %s", r.WorkloadName)
		}
		if r.WorkloadName == "static" && r.Vulnerabilities[0].Severity != "HIGH" {
			t.Fatalf("sévérité non normalisée : %+v", r.Vulnerabilities[0])
		}
	}
}

func TestAddRouteBackends(t *testing.T) {
	route := func(kind string, spec map[string]any) *unstructured.Unstructured {
		u := &unstructured.Unstructured{Object: map[string]any{"kind": kind, "spec": spec}}
		u.SetNamespace("ns")
		u.SetName("r")
		return u
	}
	eps := entrypoints{}
	addRouteBackends(eps, gateway, route("HTTPRoute", map[string]any{"rules": []any{
		map[string]any{"backendRefs": []any{
			map[string]any{"name": "web"},
			map[string]any{"name": "api", "namespace": "autre"},
			map[string]any{"name": "import", "kind": "ServiceImport"},
		}},
	}}), false)
	addRouteBackends(eps, traefik, route("IngressRouteTCP", map[string]any{"routes": []any{
		map[string]any{"services": []any{map[string]any{"name": "db"}, map[string]any{"name": "wrr", "kind": "TraefikService"}}},
	}}), false)
	want := map[serviceKey]string{{"ns", "web"}: "HTTPRoute/r", {"autre", "api"}: "HTTPRoute/r", {"ns", "db"}: "IngressRouteTCP/r"}
	if len(eps) != len(want) {
		t.Fatalf("entrées inattendues : %v", eps)
	}
	for k, v := range want {
		if got := eps[k]; len(got) != 1 || got[0].via != v || got[0].internal {
			t.Errorf("%v : %v, attendu %s", k, got, v)
		}
	}
}

func TestRouteInternal(t *testing.T) {
	cfg := config.Default().Collect
	cfg.InternalGateways = []string{"infra/privee"}
	cfg.InternalGatewayClasses = []string{"interne"}
	policy := newExposurePolicy(cfg)

	gw := func(ns, name, class string, ann map[string]any) *unstructured.Unstructured {
		spec := map[string]any{"gatewayClassName": class}
		if ann != nil {
			spec["infrastructure"] = map[string]any{"annotations": ann}
		}
		u := &unstructured.Unstructured{Object: map[string]any{"kind": "Gateway", "spec": spec}}
		u.SetNamespace(ns)
		u.SetName(name)
		return u
	}
	internalGws := map[string]bool{}
	for _, g := range []*unstructured.Unstructured{
		gw("infra", "publique", "traefik", nil),
		gw("infra", "classe", "interne", nil),
		gw("infra", "annotee", "traefik", map[string]any{"service.beta.kubernetes.io/aws-load-balancer-scheme": "Internal"}),
		gw("infra", "annotee-publique", "traefik", map[string]any{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing"}),
	} {
		if gatewayInternal(g, policy) {
			internalGws[g.GetNamespace()+"/"+g.GetName()] = true
		}
	}
	if want := map[string]bool{"infra/classe": true, "infra/annotee": true}; !maps.Equal(internalGws, want) {
		t.Fatalf("Gateways internes : %v, attendu %v", internalGws, want)
	}

	route := func(parents ...any) *unstructured.Unstructured {
		u := &unstructured.Unstructured{Object: map[string]any{"kind": "HTTPRoute", "spec": map[string]any{"parentRefs": parents}}}
		u.SetNamespace("app")
		u.SetName("r")
		return u
	}
	ref := func(kv ...string) map[string]any {
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	tests := []struct {
		name  string
		route *unstructured.Unstructured
		want  bool
	}{
		{"sans parent", route(), false},
		{"Gateway publique", route(ref("name", "publique", "namespace", "infra")), false},
		{"Gateway interne par sa classe", route(ref("name", "classe", "namespace", "infra")), true},
		{"Gateway interne par ses annotations", route(ref("name", "annotee", "namespace", "infra", "kind", "Gateway", "group", "gateway.networking.k8s.io")), true},
		{"Gateway interne par la configuration, même non observée", route(ref("name", "privee", "namespace", "infra")), true},
		{"namespace par défaut : celui de la route", route(ref("name", "classe")), false},
		{"une Gateway interne et une publique", route(ref("name", "classe", "namespace", "infra"), ref("name", "publique", "namespace", "infra")), false},
		{"maillage : parent Service", route(ref("name", "web", "kind", "Service", "group", "")), true},
		{"parent d'un autre type", route(ref("name", "x", "kind", "ListenerSet", "group", "gateway.networking.x-k8s.io")), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := routeInternal(tt.route, internalGws, policy); got != tt.want {
				t.Fatalf("interne : %v, attendu %v", got, tt.want)
			}
		})
	}
}

func TestWaitQuiet(t *testing.T) {
	c := &Collector{changed: make(chan struct{}, 1)}
	a := &Loop{Collector: c, Debounce: 50 * time.Millisecond, Interval: time.Second}

	// Des changements toutes les 20 ms repoussent l'envoi jusqu'au calme.
	stop := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			select {
			case c.changed <- struct{}{}:
			case <-stop:
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	start := time.Now()
	if !a.waitQuiet(context.Background()) {
		t.Fatal("attente interrompue")
	}
	close(stop)
	if d := time.Since(start); d < 200*time.Millisecond {
		t.Fatalf("envoi pendant la rafale, après %s", d)
	}

	// Un flot continu n'empêche pas l'envoi au-delà d'Interval.
	a.Interval = 150 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			select {
			case c.changed <- struct{}{}:
			default:
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	start = time.Now()
	if !a.waitQuiet(ctx) {
		t.Fatal("attente interrompue")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("attente non bornée : %s", d)
	}

	cancel()
	if a.waitQuiet(ctx) {
		t.Fatal("un contexte annulé doit interrompre l'attente")
	}
}

// slowDest simule un envoi qui dure.
type slowDest struct {
	d    time.Duration
	done chan error
}

func (s *slowDest) Send(ctx context.Context, _ *model.Snapshot) (model.IngestReply, error) {
	select {
	case <-time.After(s.d):
		s.done <- nil
		return model.IngestReply{}, nil
	case <-ctx.Done():
		s.done <- ctx.Err()
		return model.IngestReply{}, ctx.Err()
	}
}

func (s *slowDest) SendSBOMs(context.Context, *model.SBOMUpload) (model.SBOMReply, error) {
	return model.SBOMReply{}, nil
}

func emptyCollector() *Collector {
	// Client factice : la découverte ne trouve aucune route.
	c := &Collector{changed: make(chan struct{}, 1), kube: fake.NewClientset(), routes: map[string]*routeInformer{}}
	c.source = &OperatorSource{lister: cache.NewGenericLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}), gvrVulnReports.GroupResource())}
	c.listers.rs = func() []*appsv1.ReplicaSet { return nil }
	c.listers.rc = func() []*corev1.ReplicationController { return nil }
	c.listers.ds = func() []*appsv1.DaemonSet { return nil }
	c.listers.sts = func() []*appsv1.StatefulSet { return nil }
	c.listers.job = func() []*batchv1.Job { return nil }
	c.listers.cj = func() []*batchv1.CronJob { return nil }
	c.listers.pod = func() []*corev1.Pod { return nil }
	c.listers.svc = func() []*corev1.Service { return nil }
	c.ingresses = func() ([]*unstructuredIngress, error) { return nil, nil }
	return c
}

func TestPushFinishesDuringShutdown(t *testing.T) {
	for _, tt := range []struct {
		name     string
		send     time.Duration
		grace    time.Duration
		finishes bool
	}{
		{"envoi plus court que le délai d'arrêt", 200 * time.Millisecond, time.Second, true},
		{"envoi plus long que le délai d'arrêt", 2 * time.Second, 100 * time.Millisecond, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dest := &slowDest{d: tt.send, done: make(chan error, 1)}
			l := &Loop{Collector: emptyCollector(), Destination: dest, ShutdownTimeout: tt.grace}
			ctx, cancel := context.WithCancel(context.Background())
			go func() { time.Sleep(50 * time.Millisecond); cancel() }()
			l.push(ctx)
			err := <-dest.done
			if (err == nil) != tt.finishes {
				t.Fatalf("envoi terminé : %v, attendu %v", err == nil, tt.finishes)
			}
			if !l.Alive(time.Minute, time.Now()) || l.Alive(time.Millisecond, time.Now().Add(time.Hour)) {
				t.Fatal("signal de vie incohérent")
			}
		})
	}
}

func TestRetryDelay(t *testing.T) {
	l := &Loop{Interval: 10 * time.Minute, RetryInterval: 15 * time.Second}
	plain := errors.New("injoignable")
	for failures, want := range map[int]time.Duration{1: 15 * time.Second, 2: 30 * time.Second, 3: time.Minute, 10: 10 * time.Minute} {
		if got := l.retryDelay(failures, plain); got != want {
			t.Errorf("%d échecs : %s, attendu %s", failures, got, want)
		}
	}
	ra := &RetryAfterError{Err: plain, After: 2 * time.Minute}
	if got := l.retryDelay(1, ra); got != 2*time.Minute {
		t.Errorf("Retry-After : %s", got)
	}
	ra.After = time.Hour
	if got := l.retryDelay(1, ra); got != 10*time.Minute {
		t.Errorf("Retry-After plafonné : %s", got)
	}
}

func TestSendRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "saturé", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	cfg := validAgent()
	cfg.ServerURL = srv.URL
	d, _ := NewHTTPDestination(cfg)
	var ra *RetryAfterError
	if _, err := d.Send(context.Background(), &model.Snapshot{}); !errors.As(err, &ra) || ra.After != 30*time.Second {
		t.Fatalf("Retry-After non transmis : %v", err)
	}
}

// Après un échec, l'agent réessaie bien avant l'intervalle.
func TestLoopRetriesAfterFailure(t *testing.T) {
	dest := &flakyDest{fail: 2, sent: make(chan struct{}, 10)}
	l := &Loop{Collector: emptyCollector(), Destination: dest, Interval: time.Hour, RetryInterval: 50 * time.Millisecond, ShutdownTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)
	select {
	case <-dest.sent:
	case <-time.After(5 * time.Second):
		t.Fatal("aucun nouvel essai après l'échec")
	}
	if dest.calls.Load() != 3 {
		t.Fatalf("%d tentatives, 3 attendues", dest.calls.Load())
	}
}

type flakyDest struct {
	fail  int32
	calls atomic.Int32
	sent  chan struct{}
}

func (f *flakyDest) Send(context.Context, *model.Snapshot) (model.IngestReply, error) {
	if n := f.calls.Add(1); n <= f.fail {
		return model.IngestReply{}, errors.New("panne passagère")
	}
	f.sent <- struct{}{}
	return model.IngestReply{}, nil
}

func (f *flakyDest) SendSBOMs(context.Context, *model.SBOMUpload) (model.SBOMReply, error) {
	return model.SBOMReply{}, nil
}

// Recherche par le serveur avec l'opérateur : les SbomReport remplacent
// les VulnerabilityReport, gardés en mémoire sans leurs composants.
func TestOperatorServerMatch(t *testing.T) {
	op := NewOperatorSource(true)
	if op.reports() != gvrSbomReports || !op.ServerMatch() || op.Required()[0].Resource != "sbomreports" {
		t.Fatalf("ressource lue : %v", op.reports())
	}
	if NewOperatorSource(false).reports() != gvrVulnReports {
		t.Fatal("sans serverMatch : VulnerabilityReport attendus")
	}
	u := report("sbom", map[string]string{lblKind: "Pod", lblName: "static", lblNamespace: "ns", lblContainer: "c"}, nil, nil)
	u.SetKind("SbomReport")
	unstructured.SetNestedField(u.Object, map[string]any{"bomFormat": "CycloneDX", "components": []any{map[string]any{"purl": "pkg:apk/alpine/busybox@1"}}}, "report", "components")
	obj, err := stripComponents(u)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := unstructured.NestedFieldNoCopy(obj.(*unstructured.Unstructured).Object, "report", "components"); ok {
		t.Fatal("composants gardés en mémoire")
	}
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	indexer.Add(obj)
	op.lister = cache.NewGenericLister(indexer, gvrSbomReports.GroupResource())
	reports, err := op.Reports()
	if err != nil || len(reports) != 1 {
		t.Fatalf("rapports : %v %v", reports, err)
	}
	r := reports[0]
	if r.Report.Digest != "sha256:abc" || r.Report.Repository != "library/nginx" || len(r.Report.Vulnerabilities) != 0 || r.object.name != "sbom" {
		t.Fatalf("rapport : %+v", r)
	}
	if refs := op.sbomRefs(reports); refs["sha256:abc"].name != "sbom" {
		t.Fatalf("SBOM de l'image : %+v", refs)
	}
}

func TestServerMatchNeedsInventory(t *testing.T) {
	c, s := validCollect(), config.Default().Scanner
	c.Source, c.Inventory, s.ServerMatch = model.SourceOperator, false, true
	if err := ValidateSources(c, s); err == nil || !strings.Contains(err.Error(), "collect.inventory") {
		t.Fatalf("serverMatch sans inventaire : %v", err)
	}
}

// Un snapshot identique au dernier accepté n'est renvoyé qu'à l'intervalle ;
// un contenu différent part tout de suite.
func TestPushSkipsUnchangedSnapshot(t *testing.T) {
	dest := &flakyDest{sent: make(chan struct{}, 10)}
	l := &Loop{Collector: emptyCollector(), Destination: dest, Interval: time.Hour, ShutdownTimeout: time.Second}
	ctx := context.Background()
	for range 3 {
		if err := l.push(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := dest.calls.Load(); n != 1 {
		t.Fatalf("snapshot inchangé : %d envois, 1 attendu", n)
	}
	l.lastSent[0] ^= 1 // contenu différent du dernier accepté
	l.push(ctx)
	if n := dest.calls.Load(); n != 2 {
		t.Fatalf("snapshot changé : %d envois, 2 attendus", n)
	}
	l.Interval = time.Nanosecond // intervalle écoulé : signal de vie
	l.push(ctx)
	if n := dest.calls.Load(); n != 3 {
		t.Fatalf("intervalle écoulé : %d envois, 3 attendus", n)
	}
	// Un échec n'enregistre pas d'empreinte : le même snapshot repart.
	failing := &flakyDest{fail: 1, sent: make(chan struct{}, 10)}
	l = &Loop{Collector: emptyCollector(), Destination: failing, Interval: time.Hour, ShutdownTimeout: time.Second}
	l.push(ctx)
	l.push(ctx)
	if n := failing.calls.Load(); n != 2 {
		t.Fatalf("après un échec : %d envois, 2 attendus", n)
	}
	// L'heure de collecte n'entre pas dans l'empreinte.
	a, b := model.Snapshot{Cluster: "c", CollectedAt: time.Unix(1, 0)}, model.Snapshot{Cluster: "c", CollectedAt: time.Unix(2, 0)}
	if fingerprint(&a) != fingerprint(&b) {
		t.Fatal("empreinte dépendante de l'heure de collecte")
	}
}
