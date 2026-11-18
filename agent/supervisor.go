package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/model"
	"github.com/ThomasSamson/wardpod-agent/scanner"
	"k8s.io/client-go/rest"
)

// Supervisor choisit la source des vulnérabilités et fait tourner la
// collecte. En mode auto, il réévalue le choix périodiquement : installer ou
// retirer le Trivy Operator bascule la source sans redémarrage.
type Supervisor struct {
	Collect         config.Collect
	Scanner         config.Scanner
	Version         string
	RC              *rest.Config
	Destination     Destination
	ShutdownTimeout time.Duration

	loop      atomic.Pointer[Loop]
	collector atomic.Pointer[Collector]
	notify    atomic.Pointer[func()]
	source    atomic.Pointer[string]
	scMu      sync.Mutex
	sc        *scanner.Scanner
}

// Ready indique que la collecte courante a synchronisé ses caches.
func (s *Supervisor) Ready() bool {
	c := s.collector.Load()
	return c != nil && c.Ready()
}

// Alive indique que la boucle d'envoi courante n'est pas bloquée.
func (s *Supervisor) Alive(maxAge time.Duration, now time.Time) bool {
	l := s.loop.Load()
	return l == nil || l.Alive(maxAge, now)
}

// Collector renvoie la collecte courante (nil avant le premier démarrage).
func (s *Supervisor) Collector() *Collector { return s.collector.Load() }

// ScannerStatus renvoie l'état du scanner intégré s'il a été créé.
func (s *Supervisor) ScannerStatus() (scanner.Status, bool) {
	s.scMu.Lock()
	sc := s.sc
	s.scMu.Unlock()
	if sc == nil {
		return scanner.Status{}, false
	}
	return sc.Status(), true
}

// decide renvoie la source à utiliser : celle imposée, ou en mode auto
// l'opérateur s'il est servi et lisible, sinon le scanner intégré.
func (s *Supervisor) decide(ctx context.Context) (string, error) {
	if s.Collect.Source != "auto" {
		return s.Collect.Source, nil
	}
	op := NewOperatorSource(s.Scanner.ServerMatch)
	probe, err := NewCollector(s.Collect, s.Version, s.RC, op)
	if err != nil {
		return "", err
	}
	gvr := op.reports()
	ok, err := probe.served(gvr)
	if err != nil {
		return "", fmt.Errorf("découverte du Trivy Operator : %w", err)
	}
	if ok && probe.allowed(ctx, GroupResource{gvr.Group, gvr.Resource}) == nil {
		return model.SourceOperator, nil
	}
	return model.SourceBuiltin, nil
}

// closeScanner efface les identifiants de registre du scanner, s'il a servi.
func (s *Supervisor) closeScanner() {
	s.scMu.Lock()
	defer s.scMu.Unlock()
	if s.sc != nil {
		s.sc.Close()
	}
}

// NewSource construit la source demandée ; le scanner intégré est créé une
// fois et garde ses résultats d'une activation à l'autre.
func (s *Supervisor) newSource(kind string) (Source, error) {
	if kind == model.SourceOperator {
		return NewOperatorSource(s.Scanner.ServerMatch), nil
	}
	s.scMu.Lock()
	defer s.scMu.Unlock()
	if s.sc == nil {
		sc, err := scanner.New(s.Scanner, func() {
			if f := s.notify.Load(); f != nil {
				(*f)()
			}
		})
		if err != nil {
			return nil, err
		}
		s.sc = sc
	}
	return NewBuiltinSource(s.sc), nil
}

// Run fait tourner la collecte jusqu'à l'annulation du contexte.
func (s *Supervisor) Run(ctx context.Context) error {
	defer s.closeScanner()
	current := ""
	for {
		kind, err := s.decide(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if current == "" {
				return err
			}
			slog.Warn("réévaluation de la source impossible : source inchangée", "err", err)
			kind = current
		}
		if current != "" && kind != current {
			slog.Info("changement de source des vulnérabilités", "from", current, "to", kind)
			// Plus prêt tant que la nouvelle collecte n'a pas synchronisé
			// ses caches.
			s.collector.Store(nil)
		}
		current = kind
		switched, err := s.runOnce(ctx, kind)
		if err != nil {
			return err
		}
		if !switched {
			return nil
		}
	}
}

// runOnce fait tourner une collecte avec la source donnée. Elle s'arrête à
// l'annulation du contexte (switched faux) ou quand le mode auto choisit une
// autre source (switched vrai).
func (s *Supervisor) runOnce(ctx context.Context, kind string) (switched bool, err error) {
	source, err := s.newSource(kind)
	if err != nil {
		return false, err
	}
	collector, err := NewCollector(s.Collect, s.Version, s.RC, source)
	if err != nil {
		return false, err
	}
	// Les defer s'exécutent en ordre inverse : annuler, puis attendre.
	cctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	if b, ok := source.(*BuiltinSource); ok {
		notify := collector.notify
		s.notify.Store(&notify)
		wg.Add(1)
		go func() { defer wg.Done(); b.scanner.Run(cctx) }()
	}
	if err := collector.Start(cctx); err != nil {
		if ctx.Err() != nil {
			return false, nil
		}
		return false, err
	}
	s.collector.Store(collector)
	s.source.Store(&kind)
	loop := &Loop{Collector: collector, Destination: s.Destination, Interval: s.Collect.Interval, Debounce: s.Collect.Debounce,
		RetryInterval: s.Collect.RetryInterval, ShutdownTimeout: s.ShutdownTimeout}
	s.loop.Store(loop)
	wg.Add(1)
	go func() { defer wg.Done(); loop.Run(cctx) }()
	slog.Info("collecte démarrée", "source", kind, "cluster", s.Collect.Cluster)

	if s.Collect.Source != "auto" {
		<-ctx.Done()
		return false, nil
	}
	t := time.NewTicker(s.Collect.SourceCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, nil
		case <-t.C:
			next, err := s.decide(ctx)
			if err != nil {
				slog.Warn("réévaluation de la source impossible : source inchangée", "err", err)
				continue
			}
			if next != kind {
				return true, nil
			}
		}
	}
}

// Dump envoie un seul snapshot puis s'arrête. Avec le scanner intégré, il
// attend d'abord que les images en service soient analysées (ou en échec).
func (s *Supervisor) Dump(ctx context.Context) error {
	defer s.closeScanner()
	kind, err := s.decide(ctx)
	if err != nil {
		return err
	}
	source, err := s.newSource(kind)
	if err != nil {
		return err
	}
	collector, err := NewCollector(s.Collect, s.Version, s.RC, source)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	if b, ok := source.(*BuiltinSource); ok {
		wg.Add(1)
		go func() { defer wg.Done(); b.scanner.Run(cctx) }()
	}
	if err := collector.Start(cctx); err != nil {
		return err
	}
	collector.WantAllSBOMs()
	if err := WaitComplete(cctx, collector); err != nil {
		return err
	}
	snap, err := collector.Snapshot()
	if err != nil {
		return err
	}
	_, err = s.Destination.Send(ctx, snap)
	return err
}

// WaitComplete attend que la source n'attende plus d'analyse ni de SBOM
// (mode -dump), dans la limite du contexte.
func WaitComplete(ctx context.Context, c *Collector) error {
	for {
		if _, err := c.Snapshot(); err != nil {
			return err
		}
		inc, ok := c.source.(interface{ Pending() bool })
		if (!ok || !inc.Pending()) && (c.inv == nil || !c.inv.pending()) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("images encore en cours d'analyse : %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}
