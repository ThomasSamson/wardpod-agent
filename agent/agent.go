package agent

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

// Loop pousse les snapshots d'un collecteur vers une destination : à chaque
// intervalle, et après chaque rafale de changements.
type Loop struct {
	Collector   *Collector
	Destination Destination
	Interval    time.Duration
	Debounce    time.Duration
	// RetryInterval est le premier délai avant un nouvel essai après un
	// échec ; il double ensuite, plafonné à Interval.
	RetryInterval time.Duration
	// ShutdownTimeout laisse un envoi en cours se terminer après l'arrêt
	// demandé (facteur IX).
	ShutdownTimeout time.Duration

	lastSuccess atomic.Int64 // UnixNano du dernier envoi réussi
	lastAttempt atomic.Int64 // UnixNano de la dernière tentative, réussie ou non
}

// Run tourne jusqu'à l'annulation du contexte. Le collecteur doit être
// démarré.
func (l *Loop) Run(ctx context.Context) {
	ticker := time.NewTicker(l.Interval)
	defer ticker.Stop()
	// retry se déclenche après un échec, bien avant l'intervalle suivant.
	retry := time.NewTimer(time.Hour)
	retry.Stop()
	defer retry.Stop()
	failures := 0
	attempt := func() {
		l.Collector.RefreshRoutes(ctx)
		err := l.push(ctx)
		retry.Stop()
		if err == nil || ctx.Err() != nil {
			failures = 0
			return
		}
		failures++
		delay := l.retryDelay(failures, err)
		slog.Info("nouvel essai programmé", "in", delay)
		retry.Reset(delay)
	}
	attempt()
	// Au démarrage les informers ont déjà notifié : on vide le signal.
	select {
	case <-l.Collector.Changed():
	default:
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			attempt()
		case <-retry.C:
			attempt()
			ticker.Reset(l.Interval)
		case <-l.Collector.Changed():
			if !l.waitQuiet(ctx) {
				return
			}
			attempt()
			ticker.Reset(l.Interval)
		}
	}
}

// retryDelay double le délai à chaque échec, sans dépasser Interval ; un
// Retry-After du serveur l'emporte s'il est plus long.
func (l *Loop) retryDelay(failures int, err error) time.Duration {
	base := l.RetryInterval
	if base <= 0 {
		base = l.Interval
	}
	d := base
	for i := 1; i < failures && d < l.Interval; i++ {
		d *= 2
	}
	d = min(d, l.Interval)
	var ra *RetryAfterError
	if errors.As(err, &ra) && ra.After > d {
		d = min(ra.After, l.Interval)
	}
	return d
}

// Alive indique que la boucle tourne : une tentative d'envoi a eu lieu
// depuis moins de maxAge. Un serveur injoignable ne la rend pas « morte » :
// seule une boucle bloquée le fait, et un redémarrage y remédie.
func (l *Loop) Alive(maxAge time.Duration, now time.Time) bool {
	n := l.lastAttempt.Load()
	return n == 0 || now.Sub(time.Unix(0, n)) < maxAge
}

// LastSuccess renvoie l'heure du dernier envoi réussi (zéro sinon).
func (l *Loop) LastSuccess() time.Time {
	if n := l.lastSuccess.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// waitQuiet attend que le Trivy Operator ait fini sa rafale d'écritures :
// aucun changement pendant Debounce. Pendant un rescan, l'opérateur supprime
// puis recrée ses rapports : pousser au milieu enverrait un état partiel.
// L'attente est bornée par Interval pour qu'un flot continu n'empêche pas
// tout envoi. Elle renvoie false si le contexte est annulé.
func (l *Loop) waitQuiet(ctx context.Context) bool {
	deadline := time.Now().Add(l.Interval)
	timer := time.NewTimer(l.Debounce)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-l.Collector.Changed():
			timer.Reset(min(l.Debounce, time.Until(deadline)))
		case <-timer.C:
			return true
		}
	}
}

func (l *Loop) push(ctx context.Context) error {
	start := time.Now()
	defer func() { l.lastAttempt.Store(time.Now().UnixNano()) }()
	snap, err := l.Collector.Snapshot()
	if err != nil {
		slog.Error("construction du snapshot", "err", err)
		return err
	}
	// Un envoi commencé n'est pas coupé net par l'arrêt : il dispose encore
	// de ShutdownTimeout.
	sendCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		t := time.AfterFunc(l.ShutdownTimeout, cancel)
		context.AfterFunc(sendCtx, func() { t.Stop() })
	})
	defer stop()
	reply, err := l.Destination.Send(sendCtx, snap)
	if err != nil {
		slog.Error("envoi du snapshot", "err", err)
		return err
	}
	l.lastSuccess.Store(time.Now().UnixNano())
	l.Collector.SetWanted(reply.SBOMsWanted)
	n := 0
	for _, r := range snap.Reports {
		n += len(r.Vulnerabilities)
	}
	slog.Info("snapshot envoyé", "reports", len(snap.Reports), "workloads", len(snap.Workloads), "vulnerabilities", n,
		"sboms", len(snap.SBOMs), "sbomsWanted", len(reply.SBOMsWanted), "duration", time.Since(start).Round(time.Millisecond))
	l.pushSBOMs(sendCtx)
	return nil
}

// pushSBOMs transmet par lots les SBOM que le serveur a demandés. Chaque lot
// est enregistré seul, sans réécrire l'état du cluster. Un échec n'empêche
// pas le snapshot, déjà accepté : les SBOM restants seront redemandés au
// suivant.
func (l *Loop) pushSBOMs(ctx context.Context) {
	start, sent, stored := time.Now(), 0, 0
	for {
		up := l.Collector.SBOMUpload()
		if up == nil {
			break
		}
		reply, err := l.Destination.SendSBOMs(ctx, up)
		if err != nil {
			slog.Warn("envoi des SBOM : les suivants partiront après le prochain snapshot", "sent", sent, "err", err)
			break
		}
		l.Collector.SBOMsSent(up)
		sent += len(up.SBOMs)
		stored += reply.Stored
	}
	if sent > 0 {
		slog.Info("SBOM envoyés", "sboms", sent, "stored", stored, "duration", time.Since(start).Round(time.Millisecond))
	}
}
