package model

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Longueurs maximales des champs d'un snapshot : au-delà, le contenu est
// manifestement invalide (les noms Kubernetes font au plus 253 caractères).
const (
	maxNameLen  = 253
	maxShortLen = 1024
	maxTextLen  = 8192
)

// ErrInvalidSnapshot signale un snapshot refusé par Validate.
var ErrInvalidSnapshot = errors.New("snapshot invalide")

var sha256Digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// MaxUnscanned borne la liste des images non analysées d'un snapshot.
const MaxUnscanned = 100000

// validVulnerability vérifie une vulnérabilité seule.
func validVulnerability(v *Vulnerability) bool {
	if v.ID == "" || v.Score < 0 || v.Score > 10 {
		return false
	}
	for _, val := range []string{v.ID, v.Package, v.InstalledVersion, v.FixedVersion, v.Severity, v.Target, v.PURL, v.PublishedDate} {
		if len(val) > maxShortLen || strings.ContainsRune(val, 0) {
			return false
		}
	}
	for _, val := range []string{v.Title, v.PrimaryLink} {
		if len(val) > maxTextLen || strings.ContainsRune(val, 0) {
			return false
		}
	}
	return true
}

// DropInvalidVulnerabilities retire les vulnérabilités invalides (champ
// trop long, octet nul, score hors bornes) et renvoie leur nombre. Leur
// contenu vient des images analysées, que n'importe quel utilisateur du
// cluster choisit : une seule entrée hostile ne doit pas faire refuser tout
// le snapshot, ce qui figerait le cluster.
func (s *Snapshot) DropInvalidVulnerabilities() int {
	dropped := 0
	for i := range s.Reports {
		r := &s.Reports[i]
		kept := r.Vulnerabilities[:0]
		for j := range r.Vulnerabilities {
			if validVulnerability(&r.Vulnerabilities[j]) {
				kept = append(kept, r.Vulnerabilities[j])
			} else {
				dropped++
			}
		}
		r.Vulnerabilities = kept
	}
	return dropped
}

// Validate vérifie un snapshot reçu d'un agent : ce contenu vient d'un
// cluster, il n'est pas digne de confiance. Les liens qui ne sont pas en
// http(s) sont effacés plutôt que de faire refuser tout le snapshot ; les
// vulnérabilités invalides sont à retirer avant (DropInvalidVulnerabilities).
func (s *Snapshot) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	check := func(field, v string, max int) {
		if len(v) > max {
			bad("%s : %d caractères (maximum %d)", field, len(v), max)
		}
		if strings.ContainsRune(v, 0) {
			bad("%s : octet nul interdit", field)
		}
	}
	if s.Workloads == nil || s.Reports == nil {
		bad("workloads et reports sont obligatoires (même vides) : un snapshot est un état complet")
	}
	switch s.Source {
	case "", SourceOperator, SourceBuiltin:
	default:
		bad("source inconnue %q", s.Source)
	}
	check("cluster", s.Cluster, maxNameLen)
	check("environment", s.Environment, maxNameLen)
	check("agentVersion", s.AgentVersion, maxShortLen)
	check("agentInstance", s.AgentInstance, maxNameLen)
	if len(s.Unscanned) > MaxUnscanned {
		bad("unscanned : %d images (maximum %d)", len(s.Unscanned), MaxUnscanned)
	}
	for i, d := range s.Unscanned {
		if !sha256Digest.MatchString(d) {
			bad("unscanned[%d] : digest sha256 attendu", i)
			break
		}
	}
	if len(s.Inventory) > MaxInventory {
		bad("inventory : %d images (maximum %d)", len(s.Inventory), MaxInventory)
	}
	for i, im := range s.Inventory {
		if !sha256Digest.MatchString(im.Digest) || !sha256Digest.MatchString(im.Fingerprint) {
			bad("inventory[%d] : digest et empreinte sha256 attendus", i)
			break
		}
	}
	validateSBOMs(s.SBOMs, bad)
	for i := range s.Workloads {
		w := &s.Workloads[i]
		p := fmt.Sprintf("workloads[%d]", i)
		if w.Namespace == "" || w.Kind == "" || w.Name == "" {
			bad("%s : namespace, kind et name sont obligatoires", p)
		}
		for f, v := range map[string]string{"namespace": w.Namespace, "kind": w.Kind, "name": w.Name, "ownerKind": w.OwnerKind, "ownerName": w.OwnerName} {
			check(p+"."+f, v, maxNameLen)
		}
		switch w.Exposure {
		case "", ExposureNone, ExposureCluster, ExposureInternet:
		default:
			bad("%s.exposure : valeur inconnue %q", p, w.Exposure)
		}
		for j, v := range w.ExposedVia {
			check(fmt.Sprintf("%s.exposedVia[%d]", p, j), v, maxShortLen)
		}
		for j, c := range w.Containers {
			check(fmt.Sprintf("%s.containers[%d].name", p, j), c.Name, maxNameLen)
			check(fmt.Sprintf("%s.containers[%d].image", p, j), c.Image, maxShortLen)
			for _, cap := range c.Security.DangerousCaps {
				check(fmt.Sprintf("%s.containers[%d].dangerousCaps", p, j), cap, maxNameLen)
			}
		}
		if len(errs) > 20 {
			break
		}
	}
	for i := range s.Reports {
		r := &s.Reports[i]
		p := fmt.Sprintf("reports[%d]", i)
		if r.Namespace == "" || r.WorkloadKind == "" || r.WorkloadName == "" {
			bad("%s : namespace, workloadKind et workloadName sont obligatoires", p)
		}
		for f, v := range map[string]string{"namespace": r.Namespace, "workloadKind": r.WorkloadKind, "workloadName": r.WorkloadName,
			"container": r.Container, "registry": r.Registry, "repository": r.Repository, "tag": r.Tag, "digest": r.Digest,
			"osFamily": r.OSFamily, "osName": r.OSName, "scannerVersion": r.ScannerVersion} {
			check(p+"."+f, v, maxShortLen)
		}
		for j := range r.Vulnerabilities {
			v := &r.Vulnerabilities[j]
			vp := fmt.Sprintf("%s.vulnerabilities[%d]", p, j)
			if v.ID == "" {
				bad("%s.id : obligatoire", vp)
			}
			if v.Score < 0 || v.Score > 10 {
				bad("%s.score : CVSS hors de [0, 10] (%v)", vp, v.Score)
			}
			for f, val := range map[string]string{"id": v.ID, "package": v.Package, "installedVersion": v.InstalledVersion,
				"fixedVersion": v.FixedVersion, "severity": v.Severity, "target": v.Target, "purl": v.PURL, "publishedDate": v.PublishedDate} {
				check(vp+"."+f, val, maxShortLen)
			}
			check(vp+".title", v.Title, maxTextLen)
			check(vp+".primaryLink", v.PrimaryLink, maxTextLen)
			if v.PrimaryLink != "" && !httpLink(v.PrimaryLink) {
				v.PrimaryLink = ""
			}
			if len(errs) > 20 {
				break
			}
		}
		if len(errs) > 20 {
			break
		}
	}
	if len(errs) > 0 {
		if len(errs) > 20 {
			errs = append(errs[:20], errors.New("…"))
		}
		return fmt.Errorf("%w : %w", ErrInvalidSnapshot, errors.Join(errs...))
	}
	return nil
}

// validateSBOMs borne les SBOM transmis, dans un snapshot ou un lot.
func validateSBOMs(sboms []SBOM, bad func(format string, a ...any)) {
	if len(sboms) > MaxSBOMs {
		bad("sboms : %d images (maximum %d)", len(sboms), MaxSBOMs)
	}
	for i, sb := range sboms {
		if !sha256Digest.MatchString(sb.Digest) || !sha256Digest.MatchString(sb.Fingerprint) {
			bad("sboms[%d] : digest et empreinte sha256 attendus", i)
			break
		}
		if len(sb.Components) > MaxComponents {
			bad("sboms[%d] : %d composants (maximum %d)", i, len(sb.Components), MaxComponents)
			break
		}
		if len(sb.Document) > MaxDocumentBytes {
			bad("sboms[%d] : document de %d octets (maximum %d)", i, len(sb.Document), MaxDocumentBytes)
			break
		}
	}
}

func httpLink(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}
