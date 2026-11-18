package agent

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// serviceKey identifie un Service ciblé par une route d'entrée.
type serviceKey struct{ Namespace, Name string }

// entrypoint est une ressource qui publie un Service. internal la limite au
// réseau privé : route rattachée à des Gateways internes, ou à un Service
// (maillage, GAMMA).
type entrypoint struct {
	via      string
	internal bool
}

// entrypoints associe chaque Service publié à la liste des ressources qui le
// publient (Ingress, HTTPRoute, IngressRoute).
type entrypoints map[serviceKey][]entrypoint

func (e entrypoints) add(ns, svc, via string, internal bool) {
	k := serviceKey{ns, svc}
	e[k] = append(e[k], entrypoint{via, internal})
}

// exposurePolicy dit quels points d'entrée restent sur le réseau privé. Dans
// le doute, un point d'entrée est exposé sur internet.
type exposurePolicy struct {
	lbAnnotations  map[string]string // clé → valeur attendue, en minuscules
	gateways       map[string]bool   // namespace/nom
	gatewayClasses map[string]bool
}

func newExposurePolicy(c config.Collect) exposurePolicy {
	p := exposurePolicy{lbAnnotations: map[string]string{}, gateways: map[string]bool{}, gatewayClasses: map[string]bool{}}
	for _, a := range c.InternalLoadBalancerAnnotations {
		if k, v, ok := strings.Cut(a, "="); ok {
			p.lbAnnotations[strings.TrimSpace(k)] = strings.ToLower(strings.TrimSpace(v))
		}
	}
	for _, g := range c.InternalGateways {
		p.gateways[strings.TrimSpace(g)] = true
	}
	for _, g := range c.InternalGatewayClasses {
		p.gatewayClasses[strings.TrimSpace(g)] = true
	}
	return p
}

// internalAnnotations reconnaît un load balancer interne à ses annotations
// (celles du Service, ou spec.infrastructure.annotations d'une Gateway, que
// le contrôleur reporte sur le Service qu'il crée).
func (p exposurePolicy) internalAnnotations(ann map[string]string) bool {
	for k, v := range ann {
		if want, ok := p.lbAnnotations[k]; ok && strings.ToLower(strings.TrimSpace(v)) == want {
			return true
		}
	}
	return false
}

// internalGateway dit si une Gateway n'est joignable que du réseau privé.
func (p exposurePolicy) internalGateway(ns, name, class string, infraAnnotations map[string]string) bool {
	return p.gateways[ns+"/"+name] || (class != "" && p.gatewayClasses[class]) || p.internalAnnotations(infraAnnotations)
}

// dangerousCaps sont les capabilities qui permettent en pratique de sortir du
// conteneur ou de prendre la main sur le nœud. Les clés sont normalisées par
// normalizeCap.
var dangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true,
	"SYS_MODULE": true, "SYS_RAWIO": true, "DAC_READ_SEARCH": true, "NET_RAW": true, "BPF": true,
}

// normalizeCap ramène une capability à la forme de dangerousCaps : le runtime
// accepte aussi "CAP_SYS_ADMIN" ou "sys_admin".
func normalizeCap(c corev1.Capability) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(string(c))), "CAP_")
}

// resolveExposure calcule l'exposition d'un pod template à partir des
// Services qui le sélectionnent et des routes qui publient ces Services.
func resolveExposure(ns string, podLabels map[string]string, spec *corev1.PodSpec, services []*corev1.Service, eps entrypoints, policy exposurePolicy) (model.Exposure, []string) {
	exposure := model.ExposureNone
	var via []string
	raise := func(e model.Exposure, v string) {
		if e.Rank() > exposure.Rank() {
			exposure = e
		}
		if e == model.ExposureInternet {
			via = append(via, v)
		}
	}

	if spec.HostNetwork {
		raise(model.ExposureInternet, "hostNetwork")
	}
	for _, c := range spec.Containers {
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				raise(model.ExposureInternet, fmt.Sprintf("hostPort/%d", p.HostPort))
			}
		}
	}

	set := labels.Set(podLabels)
	for _, svc := range services {
		if svc.Namespace != ns || len(svc.Spec.Selector) == 0 {
			continue
		}
		if !labels.SelectorFromSet(svc.Spec.Selector).Matches(set) {
			continue
		}
		raise(model.ExposureCluster, "")
		switch svc.Spec.Type {
		case corev1.ServiceTypeLoadBalancer:
			// Un load balancer interne ouvre aussi des ports de nœud ; on les
			// suppose filtrés par le pare-feu du fournisseur, comme le veut
			// l'annotation qui le déclare interne.
			if !policy.internalAnnotations(svc.Annotations) {
				raise(model.ExposureInternet, fmt.Sprintf("Service/%s (%s)", svc.Name, svc.Spec.Type))
			}
		case corev1.ServiceTypeNodePort:
			raise(model.ExposureInternet, fmt.Sprintf("Service/%s (%s)", svc.Name, svc.Spec.Type))
		}
		// Les externalIPs sont routées vers le Service par chaque nœud, quel
		// que soit son type.
		if len(svc.Spec.ExternalIPs) > 0 {
			raise(model.ExposureInternet, fmt.Sprintf("Service/%s (externalIPs)", svc.Name))
		}
		for _, e := range eps[serviceKey{svc.Namespace, svc.Name}] {
			if !e.internal {
				raise(model.ExposureInternet, e.via)
			}
		}
	}

	sort.Strings(via)
	return exposure, dedup(via)
}

// securityFor agrège le securityContext du pod et du conteneur : le
// conteneur l'emporte sur le pod, comme le fait le kubelet.
func securityFor(spec *corev1.PodSpec, c *corev1.Container) model.SecurityContext {
	var s model.SecurityContext
	s.HostNamespaces = spec.HostNetwork || spec.HostPID || spec.HostIPC
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			s.HostPath = true
		}
	}
	s.AutomountSAToken = spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken

	var runAsNonRoot *bool
	var runAsUser *int64
	if psc := spec.SecurityContext; psc != nil {
		runAsNonRoot, runAsUser = psc.RunAsNonRoot, psc.RunAsUser
	}
	privEsc := true // valeur par défaut de Kubernetes
	if csc := c.SecurityContext; csc != nil {
		if csc.Privileged != nil && *csc.Privileged {
			s.Privileged = true
		}
		if csc.RunAsNonRoot != nil {
			runAsNonRoot = csc.RunAsNonRoot
		}
		if csc.RunAsUser != nil {
			runAsUser = csc.RunAsUser
		}
		if csc.AllowPrivilegeEscalation != nil {
			privEsc = *csc.AllowPrivilegeEscalation
			s.PrivEscalationExplicit = privEsc
		}
		if csc.ReadOnlyRootFilesystem != nil {
			s.ReadOnlyRootFS = *csc.ReadOnlyRootFilesystem
		}
		if csc.Capabilities != nil {
			for _, c := range csc.Capabilities.Add {
				if n := normalizeCap(c); dangerousCaps[n] && !slices.Contains(s.DangerousCaps, n) {
					s.DangerousCaps = append(s.DangerousCaps, n)
				}
			}
		}
	}
	// Kubernetes force allowPrivilegeEscalation pour un conteneur privilégié
	// ou disposant de CAP_SYS_ADMIN.
	s.PrivEscalation = privEsc || s.Privileged ||
		slices.Contains(s.DangerousCaps, "SYS_ADMIN") || slices.Contains(s.DangerousCaps, "ALL")
	switch {
	case runAsUser != nil:
		s.RootPossible = *runAsUser == 0
		s.RootExplicit = s.RootPossible
	case runAsNonRoot != nil && *runAsNonRoot:
		s.RootPossible = false
	default:
		s.RootPossible = true // dépend de l'USER de l'image : on ne peut pas exclure root
	}
	return s
}

func dedup(in []string) []string {
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}
