package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ThomasSamson/wardpod-agent/agent"
	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/version"
)

var agentCommand = command{
	summary: "collecte un cluster et envoie ses snapshots au serveur central",
	setup: func(fs *flag.FlagSet, cfg *config.Config) *action {
		// -dump est un mode ponctuel d'administration (facteur XII), pas une
		// clé de configuration : il n'a pas de variable WP_*.
		dump := fs.Bool("dump", false, "affiche un snapshot sur la sortie standard et s'arrête, sans rien envoyer")
		config.Alias(fs, "context", "collect.kubeContext")
		config.Alias(fs, "cluster", "collect.cluster")
		return &action{
			dataOnStdout: func() bool { return *dump },
			run: func(ctx context.Context, env *runEnv) error {
				return runAgent(ctx, env, *dump)
			},
		}
	},
}

func runAgent(ctx context.Context, env *runEnv, dump bool) error {
	cfg := env.cfg
	if err := errors.Join(cfg.ValidateCommon(), agent.ValidateSources(cfg.Collect, cfg.Scanner)); err != nil {
		return err
	}
	var dest agent.Destination = agent.WriterDestination{W: env.stdout}
	if !dump {
		d, err := agent.NewHTTPDestination(cfg.Agent)
		if err != nil {
			return err
		}
		dest = d
	}

	rc, err := agent.RestConfig(cfg.Collect.KubeContext, cfg.Collect.APITimeout, version.UserAgent())
	if err != nil {
		return err
	}
	sup := &agent.Supervisor{Collect: cfg.Collect, Scanner: cfg.Scanner, Version: version.Version, RC: rc, Destination: dest, ShutdownTimeout: cfg.ShutdownTimeout}

	if dump {
		// Avec le scanner intégré, le snapshot attend la fin des analyses
		// (une image en échec ne bloque pas) ; Ctrl-C l'interrompt.
		return sup.Dump(ctx)
	}

	// Une itération dure au plus l'intervalle, la découverte et l'envoi ;
	// au-delà du double, la boucle est considérée comme bloquée.
	maxAge := 2 * (cfg.Collect.Interval + cfg.Collect.SyncTimeout + cfg.Agent.HTTPTimeout)
	alive := func() bool { return sup.Alive(maxAge, time.Now()) }
	probes, err := startProbes(cfg.Agent.Listen, alive, sup.Ready, sup.Metrics())
	if err != nil {
		return err
	}
	defer shutdownServer(probes, cfg.ShutdownTimeout)

	slog.Info("démarrage de l'agent", "cluster", cfg.Collect.Cluster, "server", config.RedactURL(cfg.Agent.ServerURL), "probes", cfg.Agent.Listen, "source", cfg.Collect.Source)
	if err := sup.Run(ctx); err != nil {
		return err
	}
	slog.Info("arrêt de l'agent")
	return nil
}

// startProbes sert /healthz (la boucle n'est pas bloquée), /readyz (les
// caches sont synchronisés) et /metrics (état du scanner intégré).
// L'adresse est réservée avant le retour : une erreur de port arrête le
// démarrage.
func startProbes(addr string, alive, ready func() bool, metrics http.Handler) (*http.Server, error) {
	mux := http.NewServeMux()
	if metrics != nil {
		mux.Handle("GET /metrics", metrics)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !alive() {
			http.Error(w, "boucle d'envoi bloquée", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "caches en cours de synchronisation", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sondes : %w", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("serveur des sondes", "err", err)
		}
	}()
	return srv, nil
}

// shutdownServer arrête un serveur HTTP en laissant les requêtes en cours se
// terminer, dans la limite du délai d'arrêt.
func shutdownServer(srv *http.Server, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("arrêt du serveur HTTP", "err", err)
	}
}
