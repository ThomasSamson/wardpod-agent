// Package scanner analyse les images du cluster avec le binaire trivy, sans
// le Trivy Operator. Chaque image est analysée une fois par digest, quel que
// soit le nombre de workloads qui l'utilisent : trivy produit son SBOM en
// tirant l'image du registre, puis les vulnérabilités sont recherchées sur
// ce SBOM. Le SBOM est gardé en cache et réévalué à chaque mise à jour de la
// base, sans retélécharger l'image.
package scanner

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/model"
)

// Image est une image à analyser.
type Image struct {
	Digest string // sha256:…
	Ref    string // référence à tirer : dépôt@digest
	// Priority : plus petit d'abord, à priorité égale les images jamais
	// analysées passent avant les réévaluations.
	Priority int
}

// Result est l'analyse d'une image.
type Result struct {
	OSFamily  string
	OSName    string
	Vulns     []model.Vulnerability
	ScannedAt time.Time
	// DBUpdatedAt est la date de la base qui a servi.
	DBUpdatedAt time.Time
}

// Status décrit une image pour les journaux et les métriques.
type Status struct {
	Pending int
	Scanned int
	Failed  int
	DBAge   time.Duration
}

type entry struct {
	img         Image
	result      *Result
	sbom        string // chemin du SBOM, s'il existe
	failures    int
	nextAttempt time.Time
	lastErr     string
	running     bool
}

// Scanner analyse les images voulues par la collecte.
type Scanner struct {
	cfg     config.Scanner
	t       *trivy
	notify  func()
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]*entry // par digest
	wake    chan struct{}
	dbAt    time.Time
	dbReady bool
	// wanted : Want a été appelé au moins une fois ; avant, les images en
	// service sont inconnues et aucun SBOM n'est purgé.
	wanted bool
}

// New prépare le scanner ; notify est appelé quand de nouveaux résultats
// sont disponibles.
func New(cfg config.Scanner, notify func()) (*Scanner, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	t := &trivy{path: cfg.TrivyPath, cacheDir: cfg.CacheDir, dbRepos: cfg.DBRepository, javaRepos: cfg.JavaDBRepository}
	for _, d := range []string{cfg.CacheDir, filepath.Join(cfg.CacheDir, "tmp"), filepath.Join(cfg.CacheDir, "sbom")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("scanner.cacheDir non inscriptible : %w", err)
		}
		_ = os.Chmod(d, 0o700) // un cache existant peut être plus ouvert
	}
	// Les identifiants de registre ne vont pas dans le cache, qui peut être
	// un volume persistant : un répertoire temporaire, recréé à chaque
	// démarrage, les reçoit. L'ancien emplacement est nettoyé.
	_ = os.RemoveAll(filepath.Join(cfg.CacheDir, "docker"))
	if cfg.RegistryAuth != "" {
		dir, err := os.MkdirTemp("", "wardpod-registres-")
		if err != nil {
			return nil, err
		}
		t.dockerDir = dir
		if err := writeDockerConfig(t.dockerDir, cfg.RegistryAuth); err != nil {
			return nil, err
		}
	}
	if notify == nil {
		notify = func() {}
	}
	// Recherche par le serveur : pas de base à attendre.
	return &Scanner{cfg: cfg, t: t, notify: notify, now: time.Now, entries: map[string]*entry{}, wake: make(chan struct{}, 1),
		dbReady: cfg.ServerMatch}, nil
}

// imageSize suit la grammaire des tailles de trivy : un nombre, puis une
// unité décimale ou binaire facultative (500MB, 2GB, 2GiB, 2G).
var imageSize = regexp.MustCompile(`(?i)^[0-9]+(\.[0-9]+)?\s?([kmgtp](i?b)?|b)?$`)

// Validate vérifie la configuration du scanner, sans rien créer.
func Validate(cfg config.Scanner) error {
	var errs []error
	if cfg.TrivyPath == "" {
		errs = append(errs, errors.New("scanner.trivyPath : chemin de trivy manquant"))
	}
	if cfg.CacheDir == "" {
		errs = append(errs, errors.New("scanner.cacheDir : répertoire de cache manquant"))
	}
	if cfg.Concurrency < 1 {
		errs = append(errs, fmt.Errorf("scanner.concurrency invalide : %d (au moins 1)", cfg.Concurrency))
	}
	for name, d := range map[string]time.Duration{"timeout": cfg.Timeout, "dbUpdateInterval": cfg.DBUpdateInterval, "retryInterval": cfg.RetryInterval} {
		if d <= 0 {
			errs = append(errs, fmt.Errorf("scanner.%s invalide : %s", name, d))
		}
	}
	if cfg.MaxRetryInterval < cfg.RetryInterval {
		errs = append(errs, fmt.Errorf("scanner.maxRetryInterval (%s) inférieur à scanner.retryInterval (%s)", cfg.MaxRetryInterval, cfg.RetryInterval))
	}
	for _, p := range cfg.Exclude {
		if _, err := path.Match(p, ""); err != nil {
			errs = append(errs, fmt.Errorf("scanner.exclude : motif invalide %q", p))
		}
	}
	if cfg.MaxImageSize != "" && !imageSize.MatchString(cfg.MaxImageSize) {
		errs = append(errs, fmt.Errorf("scanner.maxImageSize invalide : %q (exemples : 500MB, 2GB, 2GiB)", cfg.MaxImageSize))
	}
	if cfg.SBOMRetention <= 0 {
		errs = append(errs, fmt.Errorf("scanner.sbomRetention invalide : %s", cfg.SBOMRetention))
	}
	if cfg.RegistryAuth != "" {
		if err := checkDockerConfig(cfg.RegistryAuth); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Check vérifie que trivy répond.
func (s *Scanner) Check(ctx context.Context) error {
	v, err := s.t.version(ctx)
	if err != nil {
		return fmt.Errorf("scanner : trivy introuvable ou inutilisable (%s) : %w", s.cfg.TrivyPath, err)
	}
	slog.Info("scanner intégré", "trivy", v, "cache", s.cfg.CacheDir)
	return nil
}

func (s *Scanner) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// excluded indique si une image est exclue de l'analyse.
func (s *Scanner) excluded(ref string) bool {
	name := ref
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	for _, p := range s.cfg.Exclude {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// sbomPath range les SBOM par digest, sans caractère risqué, compressés
// (gzip) : 10 à 20 fois moins de place.
func (s *Scanner) sbomPath(digest string) string {
	return filepath.Join(s.cfg.CacheDir, "sbom", strings.NewReplacer(":", "_", "/", "_").Replace(digest)+".cdx.json.gz")
}

// cachedSBOM renvoie le SBOM en cache d'une image, ou "". Un SBOM d'une
// version précédente, non compressé, est compressé au passage.
func (s *Scanner) cachedSBOM(digest string) string {
	path := s.sbomPath(digest)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	legacy := strings.TrimSuffix(path, ".gz")
	if _, err := os.Stat(legacy); err != nil {
		return ""
	}
	if err := compressFile(legacy, path); err != nil {
		slog.Warn("compression d'un SBOM en cache", "sbom", legacy, "err", err)
		return ""
	}
	return path
}

// compressFile compresse src dans dst (écriture atomique), puis supprime
// src.
func compressFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".part"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	zw := gzip.NewWriter(out)
	_, err = io.Copy(zw, in)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err == nil {
		os.Remove(src)
	}
	return err
}

// gunzipTemp décompresse r dans un fichier temporaire de dir, pour trivy,
// au plus maxSize octets. L'appelant supprime le fichier.
func gunzipTemp(dir string, r io.Reader, maxSize int64) (string, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return "", fmt.Errorf("SBOM compressé illisible : %w", err)
	}
	f, err := os.CreateTemp(dir, "sbom-*.cdx.json")
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(zr, maxSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxSize {
		err = errTooLarge
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// Want déclare les images en service. Les nouvelles entrent dans la file ;
// celles qui ne servent plus sont oubliées (leur SBOM reste en cache).
func (s *Scanner) Want(images []Image) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wanted = true
	keep := map[string]bool{}
	added := false
	for _, img := range images {
		if img.Digest == "" || s.excluded(img.Ref) {
			continue
		}
		keep[img.Digest] = true
		if e, ok := s.entries[img.Digest]; ok {
			e.img.Priority = min(e.img.Priority, img.Priority)
			continue
		}
		e := &entry{img: img}
		if e.sbom = s.cachedSBOM(img.Digest); e.sbom != "" { // SBOM déjà en cache
			now := s.now()
			_ = os.Chtimes(e.sbom, now, now) // de nouveau en service
		}
		s.entries[img.Digest] = e
		added = true
	}
	for d, e := range s.entries {
		if !keep[d] && !e.running {
			delete(s.entries, d)
			// La rétention du SBOM court à partir de maintenant.
			now := s.now()
			_ = os.Chtimes(s.sbomPath(d), now, now)
		}
	}
	if added {
		s.signal()
	}
}

// Excluded indique si la référence est exclue de l'analyse.
func (s *Scanner) Excluded(ref string) bool { return s.excluded(ref) }

// Result renvoie l'analyse d'une image, si elle est faite.
func (s *Scanner) Result(digest string) (*Result, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[digest]
	if !ok {
		return nil, "", false
	}
	return e.result, e.lastErr, e.result != nil
}

// SBOM renvoie le SBOM CycloneDX en cache d'une image en service.
func (s *Scanner) SBOM(digest string) ([]byte, error) {
	f, err := s.openSBOM(digest)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("SBOM en cache illisible : %w", err)
	}
	// Même borne que la sortie de trivy : le SBOM vient d'une image.
	data, err := io.ReadAll(io.LimitReader(zr, maxStdout+1))
	if err == nil && len(data) > maxStdout {
		err = errTooLarge
	}
	return data, err
}

// SBOMCompressed renvoie le SBOM en cache tel quel, compressé (gzip), au
// plus maxSize octets : le document complet envoyé au serveur.
func (s *Scanner) SBOMCompressed(digest string, maxSize int) ([]byte, error) {
	f, err := s.openSBOM(digest)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(maxSize)+1))
	if err == nil && len(data) > maxSize {
		err = fmt.Errorf("SBOM complet de plus de %d octets compressés", maxSize)
	}
	return data, err
}

func (s *Scanner) openSBOM(digest string) (*os.File, error) {
	s.mu.Lock()
	e, ok := s.entries[digest]
	path := ""
	if ok {
		path = e.sbom
	}
	s.mu.Unlock()
	if path == "" {
		return nil, fmt.Errorf("pas de SBOM en cache pour %s", digest)
	}
	return os.Open(path)
}

// Status résume l'état du scanner.
func (s *Scanner) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	var st Status
	for _, e := range s.entries {
		switch {
		case e.result != nil:
			st.Scanned++
		case e.lastErr != "":
			st.Failed++
		default:
			st.Pending++
		}
	}
	if !s.dbAt.IsZero() {
		st.DBAge = s.now().Sub(s.dbAt)
	}
	return st
}

// Close supprime les identifiants de registre écrits sur disque.
func (s *Scanner) Close() {
	if s.t.dockerDir != "" {
		_ = os.RemoveAll(s.t.dockerDir)
	}
}

// Run met à jour la base et analyse les images, jusqu'à l'annulation du
// contexte.
func (s *Scanner) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(1)
	if s.cfg.ServerMatch {
		go func() { defer wg.Done(); s.purgeLoop(ctx) }()
	} else {
		go func() { defer wg.Done(); s.dbLoop(ctx) }()
	}
	for range s.cfg.Concurrency {
		wg.Add(1)
		go func() { defer wg.Done(); s.worker(ctx) }()
	}
	wg.Wait()
}

// dbLoop télécharge la base au démarrage puis périodiquement ; après chaque
// mise à jour, les SBOM connus sont réévalués.
func (s *Scanner) dbLoop(ctx context.Context) {
	retry := s.cfg.RetryInterval
	for {
		err := s.t.updateDB(ctx)
		wait := s.cfg.DBUpdateInterval
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("mise à jour de la base de vulnérabilités", "err", err)
			wait = min(retry, s.cfg.DBUpdateInterval)
			retry = min(retry*2, s.cfg.MaxRetryInterval)
		} else {
			retry = s.cfg.RetryInterval
		}
		at, derr := s.t.dbUpdatedAt(ctx)
		s.mu.Lock()
		changed := derr == nil && !at.IsZero() && !at.Equal(s.dbAt)
		if derr == nil && !at.IsZero() {
			s.dbAt, s.dbReady = at, true
		}
		if changed {
			// Les résultats datent d'une base précédente : réévaluation.
			for _, e := range s.entries {
				if e.result != nil && e.result.DBUpdatedAt.Before(at) {
					e.nextAttempt = time.Time{}
				}
			}
		}
		s.mu.Unlock()
		if changed {
			slog.Info("base de vulnérabilités à jour", "updatedAt", at)
			s.signal()
		}
		s.purgeSBOMs()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// matchCached recherche les vulnérabilités d'un SBOM en cache, décompressé
// le temps de la recherche.
func (s *Scanner) matchCached(ctx context.Context, path string) (osFamily, osName string, vulns []model.Vulnerability, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", nil, err
	}
	defer f.Close()
	tmp, err := gunzipTemp(filepath.Join(s.cfg.CacheDir, "tmp"), f, maxStdout)
	if err != nil {
		return "", "", nil, err
	}
	defer os.Remove(tmp)
	return s.t.match(ctx, tmp)
}

// ServerMatch indique que le serveur recherche les vulnérabilités : le
// scanner ne fait que les SBOM.
func (s *Scanner) ServerMatch() bool { return s.cfg.ServerMatch }

// purgeLoop purge le cache des SBOM sans base à tenir à jour
// (scanner.serverMatch), au rythme de scanner.dbUpdateInterval.
func (s *Scanner) purgeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.DBUpdateInterval):
		}
		s.purgeSBOMs()
	}
}

// purgeSBOMs supprime les SBOM des images qui ne tournent plus depuis
// scanner.sbomRetention : le cache ne grossit pas sans fin.
func (s *Scanner) purgeSBOMs() {
	dir := filepath.Join(s.cfg.CacheDir, "sbom")
	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	s.mu.Lock()
	if !s.wanted {
		s.mu.Unlock()
		return
	}
	inUse := map[string]bool{}
	for d := range s.entries {
		inUse[filepath.Base(s.sbomPath(d))] = true
	}
	s.mu.Unlock()
	limit := s.now().Add(-s.cfg.SBOMRetention)
	removed := 0
	for _, f := range files {
		info, err := f.Info()
		if err != nil || inUse[f.Name()] || info.ModTime().After(limit) {
			continue
		}
		if os.Remove(filepath.Join(dir, f.Name())) == nil {
			removed++
		}
	}
	if removed > 0 {
		slog.Info("SBOM d'images retirées supprimés du cache", "count", removed)
	}
}

// next choisit le travail suivant : une image sans résultat (ou au résultat
// périmé), la plus prioritaire, dont l'attente après échec est passée.
func (s *Scanner) next() (*entry, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dbReady {
		return nil, time.Minute
	}
	now := s.now()
	var cands []*entry
	soonest := time.Duration(-1)
	for _, e := range s.entries {
		if e.running {
			continue
		}
		stale := e.result == nil || e.result.DBUpdatedAt.Before(s.dbAt)
		if !stale {
			continue
		}
		if e.nextAttempt.After(now) {
			if d := e.nextAttempt.Sub(now); soonest < 0 || d < soonest {
				soonest = d
			}
			continue
		}
		cands = append(cands, e)
	}
	if len(cands) == 0 {
		return nil, soonest
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		// Les images jamais analysées passent avant les réévaluations.
		if (a.result == nil) != (b.result == nil) {
			return a.result == nil
		}
		if a.img.Priority != b.img.Priority {
			return a.img.Priority < b.img.Priority
		}
		return a.img.Digest < b.img.Digest
	})
	e := cands[0]
	e.running = true
	if len(cands) > 1 {
		// D'autres images attendent : un autre worker est réveillé (le
		// signal n'en réveille qu'un).
		s.signal()
	}
	return e, 0
}

func (s *Scanner) worker(ctx context.Context) {
	for {
		e, wait := s.next()
		if e == nil {
			if wait < 0 {
				wait = time.Hour
			}
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
			case <-time.After(wait):
			}
			continue
		}
		s.scan(ctx, e)
		if ctx.Err() != nil {
			s.mu.Lock()
			e.running = false
			s.mu.Unlock()
			return
		}
	}
}

// scan produit le SBOM si besoin, puis recherche les vulnérabilités.
func (s *Scanner) scan(ctx context.Context, e *entry) {
	start := s.now()
	sctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	s.mu.Lock()
	img, sbom, db := e.img, e.sbom, s.dbAt
	s.mu.Unlock()

	var err error
	if sbom == "" {
		out := s.sbomPath(img.Digest)
		tmp := out + ".tmp"
		if err = s.t.sbom(sctx, img.Ref, tmp, s.cfg.MaxImageSize, s.cfg.RuntimeEnv); err == nil {
			err = compressFile(tmp, out)
		}
		_ = os.Remove(tmp)
		if err == nil {
			sbom = out
		}
	}
	var res *Result
	if err == nil && s.cfg.ServerMatch {
		// Le serveur recherche les vulnérabilités dans le SBOM complet.
		res = &Result{ScannedAt: s.now()}
	} else if err == nil {
		var osFamily, osName string
		var vulns []model.Vulnerability
		osFamily, osName, vulns, err = s.matchCached(sctx, sbom)
		if err == nil {
			res = &Result{OSFamily: osFamily, OSName: osName, Vulns: vulns, ScannedAt: s.now(), DBUpdatedAt: db}
		} else if _, statErr := os.Stat(sbom); statErr != nil {
			sbom = "" // SBOM disparu du cache : à refaire
		}
	}

	s.mu.Lock()
	e.running = false
	e.sbom = sbom
	if err != nil {
		if ctx.Err() != nil {
			s.mu.Unlock()
			return
		}
		e.failures++
		backoff := s.cfg.RetryInterval
		for i := 1; i < e.failures && backoff < s.cfg.MaxRetryInterval; i++ {
			backoff *= 2
		}
		backoff = min(backoff, s.cfg.MaxRetryInterval)
		e.nextAttempt = s.now().Add(backoff)
		e.lastErr = err.Error()
		s.mu.Unlock()
		slog.Warn("analyse d'image en échec", "image", img.Ref, "attempt", e.failures, "retryIn", backoff, "err", err)
		return
	}
	e.result, e.failures, e.lastErr, e.nextAttempt = res, 0, "", time.Time{}
	s.mu.Unlock()
	slog.Info("image analysée", "image", img.Ref, "vulnerabilities", len(res.Vulns), "duration", s.now().Sub(start).Round(time.Millisecond))
	s.notify()
}
