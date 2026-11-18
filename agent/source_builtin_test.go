package agent

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// L'historique d'un Deployment (anciens ReplicaSet) n'est pas gardé : la
// mise à jour d'image doit pouvoir corriger les vulnérabilités.
func TestStaleReplicaSets(t *testing.T) {
	ctrl := true
	rs := func(name, owner, revision string) *appsv1.ReplicaSet {
		return &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name,
			Annotations:     map[string]string{"deployment.kubernetes.io/revision": revision},
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: owner, Controller: &ctrl}}}}
	}
	c := &Collector{}
	c.listers.rs = func() []*appsv1.ReplicaSet {
		return []*appsv1.ReplicaSet{rs("web-1", "web", "1"), rs("web-2", "web", "2"), rs("api-7", "api", "7"),
			{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "seul"}}}
	}
	b := &BuiltinSource{c: c}
	stale := b.staleReplicaSets()
	if !stale[workloadKey{"app", "ReplicaSet", "web-1"}] || stale[workloadKey{"app", "ReplicaSet", "web-2"}] ||
		stale[workloadKey{"app", "ReplicaSet", "api-7"}] || stale[workloadKey{"app", "ReplicaSet", "seul"}] {
		t.Fatalf("ReplicaSet périmés : %v", stale)
	}
}
