package agent

import (
	"slices"
	"testing"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func boolp(b bool) *bool    { return &b }
func int64p(i int64) *int64 { return &i }

func TestSecurityFor(t *testing.T) {
	tests := []struct {
		name  string
		pod   corev1.PodSpec
		csc   *corev1.SecurityContext
		check func(model.SecurityContext) bool
	}{
		{"défauts Kubernetes", corev1.PodSpec{}, nil, func(s model.SecurityContext) bool {
			return s.RootPossible && s.PrivEscalation && s.AutomountSAToken && !s.Privileged && !s.RootExplicit && !s.PrivEscalationExplicit
		}},
		{"root et escalade écrits dans le manifeste", corev1.PodSpec{},
			&corev1.SecurityContext{RunAsUser: int64p(0), AllowPrivilegeEscalation: boolp(true)},
			func(s model.SecurityContext) bool {
				return s.RootPossible && s.RootExplicit && s.PrivEscalation && s.PrivEscalationExplicit
			}},
		{"durci", corev1.PodSpec{AutomountServiceAccountToken: boolp(false), SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: boolp(true)}},
			&corev1.SecurityContext{AllowPrivilegeEscalation: boolp(false), ReadOnlyRootFilesystem: boolp(true)},
			func(s model.SecurityContext) bool {
				return !s.RootPossible && !s.PrivEscalation && !s.AutomountSAToken && s.ReadOnlyRootFS
			}},
		{"runAsUser du conteneur prioritaire", corev1.PodSpec{SecurityContext: &corev1.PodSecurityContext{RunAsUser: int64p(1000)}},
			&corev1.SecurityContext{RunAsUser: int64p(0)},
			func(s model.SecurityContext) bool { return s.RootPossible }},
		{"privilégié implique l'escalade", corev1.PodSpec{}, &corev1.SecurityContext{Privileged: boolp(true), AllowPrivilegeEscalation: boolp(false)},
			func(s model.SecurityContext) bool { return s.Privileged && s.PrivEscalation }},
		{"namespaces et volumes de l'hôte", corev1.PodSpec{HostPID: true, Volumes: []corev1.Volume{{VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}}}}, nil,
			func(s model.SecurityContext) bool { return s.HostNamespaces && s.HostPath }},
		{"capabilities normalisées et dédoublonnées",
			corev1.PodSpec{},
			&corev1.SecurityContext{AllowPrivilegeEscalation: boolp(false), Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"CAP_SYS_ADMIN", "sys_admin", "net_raw", "CHOWN", "SYS_RAWIO"}}},
			func(s model.SecurityContext) bool {
				// CAP_SYS_ADMIN force l'escalade de privilèges.
				return slices.Equal(s.DangerousCaps, []string{"SYS_ADMIN", "NET_RAW", "SYS_RAWIO"}) && s.PrivEscalation
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := corev1.Container{SecurityContext: tt.csc}
			if got := securityFor(&tt.pod, &c); !tt.check(got) {
				t.Fatalf("résultat inattendu : %+v", got)
			}
		})
	}
}

func TestResolveExposure(t *testing.T) {
	podLabels := map[string]string{"app": "web", "pod-template-hash": "abc"}
	svc := func(name string, typ corev1.ServiceType, ips ...string) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name},
			Spec:       corev1.ServiceSpec{Type: typ, Selector: map[string]string{"app": "web"}, ExternalIPs: ips},
		}
	}
	annotated := func(s *corev1.Service, k, v string) *corev1.Service {
		s.Annotations = map[string]string{k: v}
		return s
	}
	policy := newExposurePolicy(config.Default().Collect)
	tests := []struct {
		name     string
		spec     corev1.PodSpec
		services []*corev1.Service
		eps      entrypoints
		want     model.Exposure
		via      []string
	}{
		{"aucun Service", corev1.PodSpec{}, nil, nil, model.ExposureNone, nil},
		{"ClusterIP", corev1.PodSpec{}, []*corev1.Service{svc("web", corev1.ServiceTypeClusterIP)}, nil, model.ExposureCluster, nil},
		{"Service d'un autre namespace ignoré", corev1.PodSpec{}, []*corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "autre", Name: "web"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{"app": "web"}},
		}}, nil, model.ExposureNone, nil},
		{"LoadBalancer", corev1.PodSpec{}, []*corev1.Service{svc("web", corev1.ServiceTypeLoadBalancer)}, nil, model.ExposureInternet, []string{"Service/web (LoadBalancer)"}},
		{"externalIPs", corev1.PodSpec{}, []*corev1.Service{svc("web", corev1.ServiceTypeClusterIP, "203.0.113.10")}, nil, model.ExposureInternet, []string{"Service/web (externalIPs)"}},
		{"Ingress et route dédoublonnés", corev1.PodSpec{}, []*corev1.Service{svc("web", corev1.ServiceTypeClusterIP)},
			entrypoints{{"ns", "web"}: {{"Ingress/web", false}, {"HTTPRoute/web", false}, {"Ingress/web", false}}}, model.ExposureInternet, []string{"HTTPRoute/web", "Ingress/web"}},
		{"route interne seule", corev1.PodSpec{}, []*corev1.Service{svc("web", corev1.ServiceTypeClusterIP)},
			entrypoints{{"ns", "web"}: {{"HTTPRoute/interne", true}}}, model.ExposureCluster, nil},
		{"route interne et route publique", corev1.PodSpec{}, []*corev1.Service{svc("web", corev1.ServiceTypeClusterIP)},
			entrypoints{{"ns", "web"}: {{"HTTPRoute/interne", true}, {"HTTPRoute/public", false}}}, model.ExposureInternet, []string{"HTTPRoute/public"}},
		{"LoadBalancer interne", corev1.PodSpec{}, []*corev1.Service{annotated(svc("web", corev1.ServiceTypeLoadBalancer),
			"service.beta.kubernetes.io/scw-loadbalancer-private", "True")}, nil, model.ExposureCluster, nil},
		{"LoadBalancer explicitement public", corev1.PodSpec{}, []*corev1.Service{annotated(svc("web", corev1.ServiceTypeLoadBalancer),
			"service.beta.kubernetes.io/scw-loadbalancer-private", "false")}, nil, model.ExposureInternet, []string{"Service/web (LoadBalancer)"}},
		{"annotation interne sans effet sur un NodePort", corev1.PodSpec{}, []*corev1.Service{annotated(svc("web", corev1.ServiceTypeNodePort),
			"service.beta.kubernetes.io/scw-loadbalancer-private", "true")}, nil, model.ExposureInternet, []string{"Service/web (NodePort)"}},
		{"hostPort", corev1.PodSpec{Containers: []corev1.Container{{Ports: []corev1.ContainerPort{{HostPort: 8443}}}}}, nil, nil, model.ExposureInternet, []string{"hostPort/8443"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, via := resolveExposure("ns", podLabels, &tt.spec, tt.services, tt.eps, policy)
			if got != tt.want || !slices.Equal(via, tt.via) {
				t.Fatalf("exposition %s via %v, attendu %s via %v", got, via, tt.want, tt.via)
			}
		})
	}
}
