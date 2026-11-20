package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/model"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const testDigest = "sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b"

// fakeTrivyBin écrit un faux trivy : une vulnérabilité pour toute image.
func fakeTrivyBin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
case "$1" in
version) echo '{"Version":"0.0-test","VulnerabilityDB":{"UpdatedAt":"2026-10-01T00:00:00Z"}}' ;;
image|convert)
  case "$*" in *--download-db-only*) exit 0 ;; esac
  for a in "$@"; do if [ "$prev" = "--output" ]; then echo '{"bomFormat":"CycloneDX"}' > "$a"; fi; prev="$a"; done ;;
sbom) echo '{"Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"}},"Results":[{"Target":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0042","PkgName":"busybox","InstalledVersion":"1","FixedVersion":"2","Severity":"HIGH"}]}]}' ;;
esac
`
	p := filepath.Join(dir, "trivy")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// runningPod crée un pod et lui donne le statut que rapporterait le kubelet.
func runningPod(ctx context.Context, t *testing.T, kube kubernetes.Interface, ns, name string, owner *metav1.OwnerReference, imageID string) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "alpine:3.19"}}},
	}
	if owner != nil {
		pod.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	p := mustCreate(kube.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{}))
	p.Status.Phase = corev1.PodRunning
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app", Image: "docker.io/library/alpine:3.19", ImageID: imageID}}
	mustCreate(kube.CoreV1().Pods(ns).UpdateStatus(ctx, p, metav1.UpdateOptions{}))
}

func TestIntegrationSupervisorBuiltinThenOperator(t *testing.T) {
	env, rc := startEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kube := kubernetes.NewForConfigOrDie(rc)
	ns := "app"
	mustCreate(kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}))

	// Un pod d'un Job lancé par un CronJob, et deux réplicas d'un même
	// ReplicaSet orphelin : une seule analyse pour le même digest.
	ctrl := true
	mustCreate(kube.BatchV1().CronJobs(ns).Create(ctx, &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "backup"},
		Spec: batchv1.CronJobSpec{Schedule: "0 3 * * *", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "app", Image: "alpine:3.19"}}},
		}}}},
	}, metav1.CreateOptions{}))
	mustCreate(kube.BatchV1().Jobs(ns).Create(ctx, &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "backup-123", OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: "backup", UID: types.UID("cj"), Controller: &ctrl}}},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"job": "backup"}},
			Spec:       corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "app", Image: "alpine:3.19"}}},
		}},
	}, metav1.CreateOptions{}))
	imageID := "docker.io/library/alpine@" + testDigest
	runningPod(ctx, t, kube, ns, "backup-123-x", &metav1.OwnerReference{APIVersion: "batch/v1", Kind: "Job", Name: "backup-123", UID: types.UID("j"), Controller: &ctrl}, imageID)
	runningPod(ctx, t, kube, ns, "seul", nil, imageID)
	// Une image chargée localement : ignorée, sans bloquer le snapshot.
	runningPod(ctx, t, kube, ns, "local", nil, "sha256:"+strings.Repeat("b", 64))

	sc := config.Default().Scanner
	sc.TrivyPath = fakeTrivyBin(t)
	sc.CacheDir = t.TempDir()
	dest := &captureDest{ch: make(chan *model.Snapshot, 16)}
	sup := &Supervisor{
		Collect: config.Collect{Cluster: "it", Interval: time.Hour, Debounce: 100 * time.Millisecond, SyncTimeout: 20 * time.Second,
			RetryInterval: time.Second, APITimeout: 10 * time.Second, Source: "auto", SourceCheckInterval: 500 * time.Millisecond},
		Scanner: sc, Version: "test", RC: rc, Destination: dest, ShutdownTimeout: time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	// Premier snapshot complet du scanner intégré.
	var snap *model.Snapshot
	for snap = dest.next(t); len(snap.Unscanned) > 0; snap = dest.next(t) {
		if snap.Source != model.SourceBuiltin {
			t.Fatalf("source %q, builtin attendue", snap.Source)
		}
	}
	if snap.Source != model.SourceBuiltin || len(snap.Reports) != 2 {
		t.Fatalf("snapshot : source %q, %d rapports", snap.Source, len(snap.Reports))
	}
	got := map[string]bool{}
	for _, r := range snap.Reports {
		got[r.WorkloadKind+"/"+r.WorkloadName] = true
		if r.Digest != testDigest || r.Repository != "library/alpine" || r.Tag != "3.19" || len(r.Vulnerabilities) != 1 {
			t.Fatalf("rapport : %+v", r)
		}
	}
	if !got["CronJob/backup"] || !got["Pod/seul"] {
		t.Fatalf("workloads : %v", got)
	}
	if st, ok := sup.ScannerStatus(); !ok || st.Scanned != 1 {
		t.Fatalf("une seule analyse attendue pour le digest partagé : %+v", st)
	}

	// Le Job du CronJob se termine : le CronJob garde ses vulnérabilités
	// jusqu'à l'exécution suivante, comme avec l'opérateur.
	done0, err := kube.CoreV1().Pods(ns).Get(ctx, "backup-123-x", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	done0.Status.Phase = corev1.PodSucceeded
	mustCreate(kube.CoreV1().Pods(ns).UpdateStatus(ctx, done0, metav1.UpdateOptions{}))
	// Un snapshot identique au précédent (qui avait le CronJob) n'est pas
	// renvoyé : rien de reçu pendant quelques secondes le prouve aussi.
	deadline0 := time.Now().Add(20 * time.Second)
	for {
		next, ok := dest.within(3 * time.Second)
		if !ok {
			break
		}
		snap = next
		var hasCron bool
		for _, r := range snap.Reports {
			hasCron = hasCron || r.WorkloadKind == "CronJob"
		}
		if !hasCron {
			t.Fatalf("CronJob terminé : ses vulnérabilités ont disparu (%d rapports)", len(snap.Reports))
		}
		if snap.CollectedAt.After(time.Now().Add(-5*time.Second)) || time.Now().After(deadline0) {
			break
		}
	}

	// Le Trivy Operator s'installe : la collecte bascule sur ses rapports.
	if _, err := envtest.InstallCRDs(env.Config, envtest.CRDInstallOptions{CRDs: []*apiextv1.CustomResourceDefinition{vulnCRD}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for snap.Source != model.SourceOperator {
		if time.Now().After(deadline) {
			t.Fatal("bascule vers le Trivy Operator non faite")
		}
		snap = dest.next(t)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
