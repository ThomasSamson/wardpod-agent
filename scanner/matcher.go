package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/model"
)

// Matcher recherche les vulnérabilités de SBOM complets avec la base de
// trivy, sans tirer d'image : la recherche faite par la console pour les
// agents qui n'envoient que les SBOM (scanner.serverMatch).
type Matcher struct {
	t *trivy
}

// NewMatcher prépare la recherche ; la base se télécharge par UpdateDB.
func NewMatcher(cfg config.Scanner) (*Matcher, error) {
	if cfg.TrivyPath == "" || cfg.CacheDir == "" {
		return nil, errors.New("scanner.trivyPath et scanner.cacheDir obligatoires pour la recherche sur les SBOM")
	}
	for _, d := range []string{cfg.CacheDir, filepath.Join(cfg.CacheDir, "tmp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("scanner.cacheDir non inscriptible : %w", err)
		}
	}
	return &Matcher{t: &trivy{path: cfg.TrivyPath, cacheDir: cfg.CacheDir, dbRepos: cfg.DBRepository, javaRepos: cfg.JavaDBRepository}}, nil
}

// UpdateDB met la base à jour et renvoie sa version (sa date de
// génération) : un résultat obtenu avec une autre version est à refaire.
func (m *Matcher) UpdateDB(ctx context.Context) (string, error) {
	if err := m.t.updateDB(ctx); err != nil {
		return "", err
	}
	at, err := m.t.dbUpdatedAt(ctx)
	if err != nil {
		return "", err
	}
	if at.IsZero() {
		return "", errors.New("base de vulnérabilités absente après la mise à jour")
	}
	return at.UTC().Format(time.RFC3339), nil
}

// Match recherche les vulnérabilités d'un SBOM CycloneDX compressé (gzip).
func (m *Matcher) Match(ctx context.Context, document []byte, maxSize int64) (osFamily, osName string, vulns []model.Vulnerability, err error) {
	tmp, err := gunzipTemp(filepath.Join(m.t.cacheDir, "tmp"), bytes.NewReader(document), maxSize)
	if err != nil {
		return "", "", nil, err
	}
	defer os.Remove(tmp)
	return m.t.match(ctx, tmp)
}
