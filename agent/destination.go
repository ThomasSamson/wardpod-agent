package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/model"
)

// Destination reçoit les snapshots. Sa réponse peut demander des SBOM, qui
// suivent par lots (SendSBOMs).
type Destination interface {
	Send(ctx context.Context, snap *model.Snapshot) (model.IngestReply, error)
	SendSBOMs(ctx context.Context, up *model.SBOMUpload) (model.SBOMReply, error)
}

// HTTPDestination envoie les snapshots au serveur central.
type HTTPDestination struct {
	cfg    config.Agent
	client *http.Client
}

// NewHTTPDestination vérifie la configuration d'envoi.
func NewHTTPDestination(cfg config.Agent) (*HTTPDestination, error) {
	if err := ValidateHTTP(cfg); err != nil {
		return nil, err
	}
	return &HTTPDestination{cfg: cfg, client: &http.Client{
		Timeout: cfg.HTTPTimeout,
		// Une redirection pourrait renvoyer le jeton vers une autre
		// destination : elle est traitée comme une erreur.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// ValidateHTTP vérifie la configuration d'envoi au serveur.
func ValidateHTTP(cfg config.Agent) error {
	var errs []error
	if cfg.Token == "" {
		errs = append(errs, errors.New("agent.token : jeton manquant"))
	}
	if err := config.CheckURL(cfg.ServerURL, cfg.AllowInsecure); err != nil {
		errs = append(errs, fmt.Errorf("agent.serverURL : %w", err))
	}
	if cfg.HTTPTimeout <= 0 {
		errs = append(errs, fmt.Errorf("agent.httpTimeout invalide : %s", cfg.HTTPTimeout))
	}
	return errors.Join(errs...)
}

func (d *HTTPDestination) Send(ctx context.Context, snap *model.Snapshot) (model.IngestReply, error) {
	var reply model.IngestReply
	return reply, d.post(ctx, "/api/v1/ingest", snap, &reply)
}

func (d *HTTPDestination) SendSBOMs(ctx context.Context, up *model.SBOMUpload) (model.SBOMReply, error) {
	var reply model.SBOMReply
	return reply, d.post(ctx, "/api/v1/sboms", up, &reply)
}

// post envoie v compressé au serveur et lit sa réponse dans reply.
func (d *HTTPDestination) post(ctx context.Context, path string, v, reply any) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(v); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(d.cfg.ServerURL, "/")+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+d.cfg.Token)
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		err := fmt.Errorf("serveur : %s : %s", resp.Status, strings.TrimSpace(string(body)))
		if secs, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && secs > 0 {
			return &RetryAfterError{Err: err, After: time.Duration(secs) * time.Second}
		}
		return err
	}
	// L'envoi est accepté : une réponse illisible (serveur d'une version
	// antérieure) ne demande simplement rien.
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxReplyBytes)).Decode(reply)
	return nil
}

// maxReplyBytes borne la réponse lue : la liste des SBOM demandés.
const maxReplyBytes = 16 << 20

// RetryAfterError porte le délai demandé par le serveur (Retry-After)
// avant un nouvel essai.
type RetryAfterError struct {
	Err   error
	After time.Duration
}

func (e *RetryAfterError) Error() string { return e.Err.Error() }
func (e *RetryAfterError) Unwrap() error { return e.Err }

// WriterDestination écrit les snapshots en JSON indenté (mode -dump).
type WriterDestination struct{ W io.Writer }

func (d WriterDestination) Send(_ context.Context, snap *model.Snapshot) (model.IngestReply, error) {
	enc := json.NewEncoder(d.W)
	enc.SetIndent("", "  ")
	return model.IngestReply{}, enc.Encode(snap)
}

// SendSBOMs n'est pas appelé en mode -dump : les SBOM sont dans le snapshot.
func (d WriterDestination) SendSBOMs(_ context.Context, up *model.SBOMUpload) (model.SBOMReply, error) {
	enc := json.NewEncoder(d.W)
	enc.SetIndent("", "  ")
	return model.SBOMReply{Stored: len(up.SBOMs)}, enc.Encode(up)
}
