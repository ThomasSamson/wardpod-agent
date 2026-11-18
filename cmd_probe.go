package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/version"
)

func init() {
	register("probe", command{
		summary: "interroge une URL de Wardpod (sonde, helm test) : code 0 si elle répond 200",
		setup: func(fs *flag.FlagSet, _ *config.Config) *action {
			// Mode ponctuel d'administration : pas de clé de configuration.
			target := fs.String("url", "", "URL à interroger, par exemple http://wardpod:8080/readyz")
			timeout := fs.Duration("timeout", 10*time.Second, "délai maximal de la requête")
			return &action{dataOnStdout: always, run: func(ctx context.Context, env *runEnv) error { return runProbe(ctx, env, *target, *timeout) }}
		},
	})
}

// runProbe permet de vérifier un déploiement depuis l'image elle-même, qui
// n'a ni shell ni client HTTP.
func runProbe(ctx context.Context, env *runEnv, target string, timeout time.Duration) error {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%w : -url doit être une URL http(s) complète (%q)", errUsage, target)
	}
	if timeout <= 0 {
		return fmt.Errorf("%w : -timeout doit être positif", errUsage)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s injoignable : %w", u.Redacted(), err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s : %s %s", u.Redacted(), resp.Status, body)
	}
	_, err = fmt.Fprintf(env.stdout, "%s : %s\n", u.Redacted(), resp.Status)
	return err
}
