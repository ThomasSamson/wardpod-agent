package scanner

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrNoRegistryDigest signale une image sans digest de registre (construite
// ou chargée localement sur le nœud) : elle ne peut pas être tirée pour
// analyse.
var ErrNoRegistryDigest = errors.New("image sans digest de registre (construite ou chargée sur le nœud) : analyse impossible")

// PullRef déduit de l'imageID rapporté par le kubelet la référence à tirer
// (dépôt@digest) et le digest.
//
//	docker-pullable://nginx@sha256:…        (dockershim)
//	docker.io/library/nginx@sha256:…        (containerd, CRI-O)
//	sha256:…                                (image locale, sans dépôt)
func PullRef(imageID string) (ref, digest string, err error) {
	id := strings.TrimPrefix(strings.TrimPrefix(imageID, "docker-pullable://"), "docker://")
	repo, dig, ok := strings.Cut(id, "@")
	if !ok || repo == "" || !sha256Digest.MatchString(dig) {
		return "", "", ErrNoRegistryDigest
	}
	// imageID vient du statut du pod : il est vérifié avant d'arriver sur la
	// ligne de commande de trivy.
	if !repository.MatchString(repo) {
		return "", "", fmt.Errorf("référence d'image invalide : %q", repo)
	}
	return repo + "@" + dig, dig, nil
}

var (
	sha256Digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	// repository : hôte facultatif (avec port), puis composants de chemin
	// en minuscules ; jamais de tiret ni de point en tête.
	repository = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]+)?/)?[a-z0-9]+([._-]+[a-z0-9]+)*(/[a-z0-9]+([._-]+[a-z0-9]+)*)*$`)
)

// SplitImage découpe une référence d'image (« nginx:1.25 »,
// « registry.example.org:5000/équipe/app@sha256:… ») en registre, dépôt et
// tag, avec les conventions de Docker Hub.
func SplitImage(image string) (registry, repository, tag string) {
	name := image
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
	}
	first, rest, hasSlash := strings.Cut(name, "/")
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		registry, repository = first, rest
	} else {
		registry, repository = "index.docker.io", name
	}
	if registry == "docker.io" {
		registry = "index.docker.io"
	}
	if registry == "index.docker.io" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}
	if tag == "" && !strings.Contains(image, "@") {
		tag = "latest"
	}
	return registry, repository, tag
}
