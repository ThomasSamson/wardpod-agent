package agent

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ThomasSamson/wardpod-agent/model"
)

// Extrait du SBOM produit par trivy (SbomReport du Trivy Operator ou
// scanner intégré) : système sans purl, composant imbriqué, trois formes de
// licence.
const sampleBOM = `{
  "bomFormat": "CycloneDX",
  "components": [
    {"type": "operating-system", "name": "debian", "version": "12.7"},
    {"type": "library", "name": "urllib3", "purl": "pkg:pypi/urllib3@2.7.0", "version": "2.7.0",
     "licenses": [{"license": {"id": "MIT"}}],
     "properties": [{"name": "aquasecurity:trivy:PkgType", "value": "python-pkg"},
                    {"name": "aquasecurity:trivy:LayerDigest", "value": "sha256:91"}]},
    {"type": "application", "name": "usr/local/bin/app",
     "components": [
       {"type": "library", "name": "stdlib", "purl": "pkg:golang/stdlib@v1.22.5",
        "licenses": [{"expression": "BSD-3-Clause OR MIT"}],
        "properties": [{"name": "aquasecurity:trivy:PkgType", "value": "gobinary"}]}
     ]},
    {"type": "library", "name": "openssl", "purl": "pkg:deb/debian/openssl@3.0.15?arch=amd64",
     "licenses": [{"license": {"name": "OpenSSL License"}}]}
  ]
}`

func TestParseCycloneDX(t *testing.T) {
	cs, err := parseCycloneDX([]byte(sampleBOM))
	if err != nil {
		t.Fatal(err)
	}
	cs = model.NormalizeComponents(cs)
	want := []model.Component{
		{PURL: "pkg:deb/debian/openssl@3.0.15?arch=amd64", Licenses: []string{"OpenSSL License"}},
		{PURL: "pkg:golang/stdlib@v1.22.5", Type: "gobinary", Licenses: []string{"BSD-3-Clause OR MIT"}},
		{PURL: "pkg:pypi/urllib3@2.7.0", Type: "python-pkg", Licenses: []string{"MIT"}},
	}
	if len(cs) != len(want) {
		t.Fatalf("composants : %+v", cs)
	}
	for i := range want {
		if cs[i].PURL != want[i].PURL || cs[i].Type != want[i].Type || !slices.Equal(cs[i].Licenses, want[i].Licenses) {
			t.Errorf("composant %d : %+v, attendu %+v", i, cs[i], want[i])
		}
	}
	if _, err := parseCycloneDX([]byte("{")); err == nil {
		t.Fatal("un SBOM illisible doit être signalé")
	}
}

// fakeLoader compte les chargements et peut échouer.
type fakeLoader struct {
	mu    sync.Mutex
	calls map[string]int
	fail  map[string]bool
}

func (f *fakeLoader) load(_ context.Context, ref sbomRef) ([]model.Component, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[ref.name]++
	if f.fail[ref.name] {
		return nil, errors.New("indisponible")
	}
	return []model.Component{{PURL: "pkg:pypi/" + ref.name + "@" + ref.version}}, nil
}

func (f *fakeLoader) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("délai dépassé : %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestInventory(t *testing.T) {
	fl := &fakeLoader{calls: map[string]int{}, fail: map[string]bool{"c": true}}
	notified := make(chan struct{}, 100)
	inv := newInventory(fl.load, time.Hour, func() { notified <- struct{}{} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go inv.run(ctx)

	inv.update(map[string]sbomRef{"sha256:a": {name: "a", version: "1"}, "sha256:b": {name: "b", version: "1"}, "sha256:c": {name: "c"}})
	waitFor(t, "chargement des SBOM", func() bool { return len(inv.declared()) == 2 && fl.count("c") == 1 })
	if inv.pending() {
		t.Fatal("un SBOM en échec n'est plus en attente")
	}
	<-notified

	// Rien n'est transmis sans demande du serveur ; la demande est bornée.
	if len(inv.sboms(10)) != 0 {
		t.Fatal("SBOM transmis sans demande")
	}
	if !inv.setWanted([]string{"sha256:a", "sha256:b", "sha256:inconnu"}) {
		t.Fatal("des SBOM demandés sont prêts")
	}
	if got := inv.sboms(1); len(got) != 1 || got[0].Digest != "sha256:a" || got[0].Fingerprint != model.Fingerprint(got[0].Components) {
		t.Fatalf("SBOM transmis : %+v", got)
	}
	if inv.setWanted([]string{"sha256:c"}) {
		t.Fatal("un SBOM en échec n'est pas prêt")
	}

	// Une nouvelle version recharge ; l'ancienne empreinte reste déclarée
	// jusque-là. Une image retirée est oubliée.
	before := inv.declared()
	inv.update(map[string]sbomRef{"sha256:a": {name: "a", version: "2"}, "sha256:c": {name: "c"}})
	waitFor(t, "rechargement", func() bool { return fl.count("a") == 2 })
	waitFor(t, "nouvelle empreinte", func() bool {
		d := inv.declared()
		return len(d) == 1 && d[0].Digest == "sha256:a" && d[0].Fingerprint != before[0].Fingerprint
	})
	if fl.count("b") != 1 || fl.count("c") != 1 {
		t.Fatalf("chargements inattendus : %v", fl.calls)
	}

	// En mode -dump, tout est transmis.
	inv.wantAll = true
	if len(inv.sboms(0)) != 1 {
		t.Fatal("mode -dump : tous les SBOM connus sont transmis")
	}
}

func TestOperatorSBOMRefs(t *testing.T) {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	mk := func(name, digest string, updated time.Time) SourceReport {
		r := SourceReport{Report: model.VulnerabilityReport{Digest: digest, UpdatedAt: updated}}
		r.object.namespace, r.object.name = "app", name
		return r
	}
	refs := (&OperatorSource{}).sbomRefs([]SourceReport{
		mk("replicaset-web-1-web", "sha256:a", at),
		mk("replicaset-web-2-web", "sha256:a", at.Add(time.Hour)), // plus récent : retenu
		mk("pod-sans-digest", "", at),
	})
	if len(refs) != 1 || refs["sha256:a"].name != "replicaset-web-2-web" || refs["sha256:a"].version == "" {
		t.Fatalf("références : %+v", refs)
	}
}

// sbomDest enregistre les lots reçus ; fail fait échouer les envois.
type sbomDest struct {
	batches [][]string
	fail    bool
}

func (d *sbomDest) Send(context.Context, *model.Snapshot) (model.IngestReply, error) {
	return model.IngestReply{}, nil
}

func (d *sbomDest) SendSBOMs(_ context.Context, up *model.SBOMUpload) (model.SBOMReply, error) {
	if d.fail {
		return model.SBOMReply{}, errors.New("serveur saturé")
	}
	var digests []string
	for _, sb := range up.SBOMs {
		digests = append(digests, sb.Digest)
	}
	d.batches = append(d.batches, digests)
	return model.SBOMReply{Stored: len(up.SBOMs)}, nil
}

// TestPushSBOMs : les SBOM demandés partent par lots de collect.sbomBatch,
// hors du snapshot ; un échec les garde pour le snapshot suivant.
func TestPushSBOMs(t *testing.T) {
	c := emptyCollector()
	c.cfg.Cluster, c.cfg.SBOMBatch = "c1", 2
	c.inv = newInventory(nil, time.Hour, func() {})
	for _, d := range []string{"sha256:a", "sha256:b", "sha256:c", "sha256:d"} {
		c.inv.entries[d] = &sbomEntry{fingerprint: "sha256:" + d[7:]}
	}
	c.SetWanted([]string{"sha256:a", "sha256:b", "sha256:c"})

	failing := &sbomDest{fail: true}
	(&Loop{Collector: c, Destination: failing}).pushSBOMs(context.Background())
	if up := c.SBOMUpload(); up == nil || len(up.SBOMs) != 2 {
		t.Fatalf("après un échec, les SBOM restent demandés : %+v", up)
	}

	dest := &sbomDest{}
	(&Loop{Collector: c, Destination: dest}).pushSBOMs(context.Background())
	if len(dest.batches) != 2 || !slices.Equal(dest.batches[0], []string{"sha256:a", "sha256:b"}) || !slices.Equal(dest.batches[1], []string{"sha256:c"}) {
		t.Fatalf("lots : %v", dest.batches)
	}
	if up := c.SBOMUpload(); up != nil {
		t.Fatalf("plus rien à transmettre : %+v", up)
	}
	// Le snapshot ne porte que les empreintes, hors mode -dump.
	snap, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.SBOMs) != 0 {
		t.Fatalf("SBOM dans le snapshot : %d", len(snap.SBOMs))
	}
}

// Recherche par le serveur : les lots joignent le SBOM complet.
func TestInventoryDocuments(t *testing.T) {
	inv := newInventory(func(context.Context, sbomRef) ([]model.Component, error) {
		return []model.Component{{PURL: "pkg:apk/alpine/busybox@1.36.1-r15", Type: "alpine"}}, nil
	}, time.Second, func() {})
	inv.document = func(d string, ref sbomRef) ([]byte, error) {
		if d == "sha256:"+strings.Repeat("b", 64) {
			return nil, errors.New("absent du cache")
		}
		if ref.name != d {
			return nil, errors.New("mauvais SBOM : " + ref.name)
		}
		return []byte("document " + d), nil
	}
	a, b := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	inv.update(map[string]sbomRef{a: {name: a}, b: {name: b}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go inv.run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for len(inv.declared()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	inv.setWanted([]string{a, b})
	out := inv.sboms(10)
	if len(out) != 2 || string(out[0].Document) != "document "+a || out[1].Document != nil {
		t.Fatalf("lots : %+v", out)
	}
}

// SBOM réels produits par trivy 0.75 (testdata) : chaque dépendance est
// rattachée à son application, binaire Go par le graphe des dépendances,
// paquet npm installé par son chemin ; paquets du système et application
// elle-même sans application.
func TestComponentApplications(t *testing.T) {
	load := func(name string) []model.Component {
		t.Helper()
		f, err := os.Open("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		cs, err := parseCycloneDX(data)
		if err != nil {
			t.Fatal(err)
		}
		return cs
	}
	app := func(cs []model.Component, prefix string) (string, bool) {
		for _, c := range cs {
			if strings.HasPrefix(c.PURL, prefix) {
				return c.Application, true
			}
		}
		return "", false
	}
	node := load("node-22-alpine.cdx.json.gz")
	for prefix, want := range map[string]string{
		"pkg:npm/npm@":         "",
		"pkg:npm/minipass@":    "usr/local/lib/node_modules/npm",
		"pkg:apk/alpine/musl@": "",
	} {
		if got, ok := app(node, prefix); !ok || got != want {
			t.Errorf("node, %s : application %q (trouvé %v), attendu %q", prefix, got, ok, want)
		}
	}
	caddy := load("caddy-2.10-alpine.cdx.json.gz")
	if got, ok := app(caddy, "pkg:golang/stdlib@"); !ok || got != "usr/bin/caddy" {
		t.Errorf("caddy, stdlib : %q %v", got, ok)
	}
	if got, ok := app(caddy, "pkg:apk/alpine/"); !ok || got != "" {
		t.Errorf("caddy, paquet du système : %q %v", got, ok)
	}
	deps := 0
	for _, c := range caddy {
		if c.Application == "usr/bin/caddy" {
			deps++
		}
	}
	if deps < 50 {
		t.Errorf("caddy : %d dépendances rattachées au binaire", deps)
	}
	for _, tc := range []struct{ path, want string }{
		{"usr/local/lib/node_modules/npm/package.json", ""},
		{"usr/local/lib/node_modules/npm/node_modules/abbrev/package.json", "usr/local/lib/node_modules/npm"},
		{"app/node_modules/@scope/outil/node_modules/x/package.json", "app/node_modules/@scope/outil"},
		{"app/node_modules/@scope/outil/package.json", ""},
		{"usr/lib/python3/site-packages/x/METADATA", ""},
	} {
		if got := nodeApplication(tc.path); got != tc.want {
			t.Errorf("nodeApplication(%q) = %q, attendu %q", tc.path, got, tc.want)
		}
	}
}
