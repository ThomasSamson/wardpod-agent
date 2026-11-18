package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Inventaire logiciel : ce que contiennent les images en service, d'après
// leur SBOM, indépendamment des vulnérabilités connues.
//
// Un snapshot déclare l'empreinte du SBOM de chaque image connue
// (Snapshot.Inventory). Le serveur demande dans sa réponse les images dont
// il n'a pas cette empreinte (IngestReply.SBOMsWanted) ; l'agent en
// transmet alors les composants par lots (SBOMUpload, POST
// /api/v1/sboms), enregistrés chacun à part, sans réécrire l'état du
// cluster. Snapshot.SBOMs, l'ancien transport dans le snapshot, reste
// accepté des agents antérieurs. L'empreinte fait foi : une image sans
// empreinte garde l'inventaire déjà connu.

// Bornes de l'inventaire d'un snapshot.
const (
	MaxInventory  = 100000 // images déclarées
	MaxSBOMs      = 10000  // SBOM transmis
	MaxComponents = 100000 // composants d'une image
	// MaxDocumentBytes borne un SBOM complet compressé (Document).
	MaxDocumentBytes = 8 << 20
	maxLicenses      = 32 // licences d'un composant
)

// ImageSBOM déclare l'empreinte du SBOM d'une image en service.
type ImageSBOM struct {
	Digest      string `json:"digest"`
	Fingerprint string `json:"fingerprint"`
}

// SBOM transmet les composants d'une image, normalisés
// (NormalizeComponents), et leur empreinte (Fingerprint).
type SBOM struct {
	Digest      string      `json:"digest"`
	Fingerprint string      `json:"fingerprint"`
	Components  []Component `json:"components"`
	// Document : le SBOM CycloneDX complet, compressé (gzip), quand le
	// serveur recherche lui-même les vulnérabilités (scanner.serverMatch).
	// Champ ajouté sans rupture.
	Document []byte `json:"document,omitempty"`
}

// Component est un paquet trouvé dans une image. Son identité est son purl ;
// le nom, la version et l'écosystème s'en déduisent (ParsePURL).
type Component struct {
	PURL string `json:"purl"`
	// Type est le type de paquet selon trivy (debian, gobinary,
	// python-pkg, jar…) : il distingue par exemple un module Go d'un
	// binaire Go.
	Type     string   `json:"type,omitempty"`
	Licenses []string `json:"licenses,omitempty"`
	// Application : l'application dont le composant est une dépendance
	// (fichier de verrouillage, binaire Go, paquet npm installé : son
	// chemin dans l'image) ; vide pour un paquet du système, un runtime ou
	// l'application elle-même.
	Application string `json:"application,omitempty"`
}

// PkgTypeRuntime : type d'un runtime (PHP, Node.js, Python…) lu dans les
// variables *_VERSION de la configuration de l'image, que trivy ne voit
// pas quand il est compilé dans l'image.
const PkgTypeRuntime = "runtime"

// SBOMUpload transmet un lot de SBOM demandés par le serveur. Le cluster
// est celui du jeton ; seules les images que le cluster a déclarées dans
// un snapshot sont retenues.
type SBOMUpload struct {
	Version int    `json:"version"`
	Cluster string `json:"cluster"`
	SBOMs   []SBOM `json:"sboms"`
}

// SBOMReply est la réponse du serveur à un lot : le nombre de SBOM
// enregistrés. Les autres (image inconnue du cluster, empreinte
// incohérente) restent demandés au snapshot suivant.
type SBOMReply struct {
	Stored int `json:"stored"`
}

// Validate vérifie un lot reçu d'un agent : son contenu vient des images
// du cluster.
func (u *SBOMUpload) Validate() error {
	var errs []error
	validateSBOMs(u.SBOMs, func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) })
	if len(u.Cluster) > maxNameLen || strings.ContainsRune(u.Cluster, 0) {
		errs = append(errs, errors.New("cluster : nom invalide"))
	}
	if len(errs) > 0 {
		return fmt.Errorf("lot de SBOM invalide : %w", errors.Join(errs...))
	}
	return nil
}

// CheckSBOMs normalise les SBOM du lot et écarte ceux dont l'empreinte ne
// correspond pas aux composants ; elle renvoie leur nombre.
func (u *SBOMUpload) CheckSBOMs() int {
	var dropped int
	u.SBOMs, dropped = checkSBOMs(u.SBOMs)
	return dropped
}

// IngestReply est la réponse du serveur à un snapshot, pour la partie qui
// intéresse l'agent.
type IngestReply struct {
	// SBOMsWanted liste les images dont le serveur n'a pas le SBOM à
	// l'empreinte déclarée : l'agent les transmet aux envois suivants.
	SBOMsWanted []string `json:"sbomsWanted,omitempty"`
}

func validText(v string, max int) bool {
	return v != "" && len(v) <= max && !strings.ContainsRune(v, 0)
}

// validComponent vérifie un composant seul : son contenu vient de l'image.
func validComponent(c *Component) bool {
	if !validText(c.PURL, maxShortLen) || !strings.HasPrefix(c.PURL, "pkg:") {
		return false
	}
	if _, _, name, _, ok := ParsePURL(c.PURL); !ok || name == "" {
		return false
	}
	if c.Type != "" && !validText(c.Type, maxNameLen) {
		return false
	}
	if c.Application != "" && !validText(c.Application, maxShortLen) {
		return false
	}
	if len(c.Licenses) > maxLicenses {
		return false
	}
	for _, l := range c.Licenses {
		if !validText(l, maxNameLen) {
			return false
		}
	}
	return true
}

// NormalizeComponents écarte les composants invalides, trie les licences,
// garde un composant par purl et trie par purl : deux sources qui trouvent
// les mêmes paquets produisent la même liste, donc la même empreinte.
func NormalizeComponents(cs []Component) []Component {
	out := make([]Component, 0, len(cs))
	for _, c := range cs {
		if !validComponent(&c) {
			continue
		}
		if len(c.Licenses) > 0 {
			ls := append([]string(nil), c.Licenses...)
			sort.Strings(ls)
			c.Licenses = dedupSorted(ls)
		} else {
			c.Licenses = nil
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PURL != out[j].PURL {
			return out[i].PURL < out[j].PURL
		}
		return out[i].Type < out[j].Type
	})
	kept := out[:0]
	for i, c := range out {
		if i > 0 && c.PURL == out[i-1].PURL {
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) > MaxComponents {
		kept = kept[:MaxComponents]
	}
	return kept
}

func dedupSorted(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Fingerprint calcule l'empreinte d'une liste de composants normalisée.
func Fingerprint(cs []Component) string {
	h := sha256.New()
	for _, c := range cs {
		h.Write([]byte(c.PURL))
		h.Write([]byte{'\t'})
		h.Write([]byte(c.Type))
		h.Write([]byte{'\t'})
		h.Write([]byte(strings.Join(c.Licenses, "\x1f")))
		if c.Application != "" {
			h.Write([]byte{'\t'})
			h.Write([]byte(c.Application))
		}
		h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// ParsePURL découpe un purl (pkg:type/namespace/name@version?qualifiers#subpath)
// en écosystème (le type, en minuscules), espace de noms, nom et version,
// décodés.
func ParsePURL(p string) (ecosystem, namespace, name, version string, ok bool) {
	rest, found := strings.CutPrefix(p, "pkg:")
	if !found {
		return "", "", "", "", false
	}
	rest = strings.TrimLeft(rest, "/")
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	typ, path, found := strings.Cut(rest, "/")
	if !found || typ == "" {
		return "", "", "", "", false
	}
	if i := strings.LastIndexByte(path, '@'); i >= 0 && i > strings.LastIndexByte(path, '/') {
		if version, ok = unescape(path[i+1:]); !ok {
			return "", "", "", "", false
		}
		path = path[:i]
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		if segs[i], ok = unescape(s); !ok {
			return "", "", "", "", false
		}
	}
	name = segs[len(segs)-1]
	namespace = strings.Join(segs[:len(segs)-1], "/")
	return strings.ToLower(typ), namespace, name, version, name != ""
}

func unescape(s string) (string, bool) {
	v, err := url.PathUnescape(s)
	return v, err == nil
}

// CheckSBOMs normalise les SBOM reçus et écarte ceux dont l'empreinte ne
// correspond pas aux composants (envoi corrompu ou agent incohérent) ;
// elle renvoie leur nombre. Le serveur les redemandera.
func (s *Snapshot) CheckSBOMs() int {
	var dropped int
	s.SBOMs, dropped = checkSBOMs(s.SBOMs)
	return dropped
}

func checkSBOMs(sboms []SBOM) ([]SBOM, int) {
	dropped := 0
	kept := sboms[:0]
	for _, sb := range sboms {
		sb.Components = NormalizeComponents(sb.Components)
		if Fingerprint(sb.Components) != sb.Fingerprint {
			dropped++
			continue
		}
		kept = append(kept, sb)
	}
	return kept, dropped
}
