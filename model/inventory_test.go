package model

import (
	"slices"
	"strings"
	"testing"
)

func TestParsePURL(t *testing.T) {
	for _, tc := range []struct {
		purl                   string
		eco, ns, name, version string
		ok                     bool
	}{
		{"pkg:deb/debian/openssl@3.0.15-1~deb12u1?arch=amd64&distro=debian-12", "deb", "debian", "openssl", "3.0.15-1~deb12u1", true},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "golang", "github.com/foo", "bar", "v1.2.3", true},
		{"pkg:npm/%40babel/core@7.24.0", "npm", "@babel", "core", "7.24.0", true},
		{"pkg:pypi/urllib3@2.7.0", "pypi", "", "urllib3", "2.7.0", true},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", "maven", "org.apache.logging.log4j", "log4j-core", "2.17.1", true},
		{"pkg:Golang/stdlib@v1.22.5#sub/path", "golang", "", "stdlib", "v1.22.5", true},
		{"pkg:generic/sans-version", "generic", "", "sans-version", "", true},
		{"pkg:npm/%zz@1", "", "", "", "", false},
		{"pkg:npm", "", "", "", "", false},
		{"npm/foo@1", "", "", "", "", false},
	} {
		eco, ns, name, version, ok := ParsePURL(tc.purl)
		if ok != tc.ok || eco != tc.eco || ns != tc.ns || name != tc.name || version != tc.version {
			t.Errorf("%s : %q %q %q %q %v", tc.purl, eco, ns, name, version, ok)
		}
	}
}

func TestNormalizeComponents(t *testing.T) {
	in := []Component{
		{PURL: "pkg:pypi/b@1", Licenses: []string{"MIT", "Apache-2.0", "MIT"}},
		{PURL: "pkg:pypi/a@1", Type: "python-pkg"},
		{PURL: "pkg:pypi/a@1", Type: "python-pkg"}, // doublon
		{PURL: ""},                 // sans purl : écarté
		{PURL: "pkg:pypi/c@1\x00"}, // octet nul : écarté
		{PURL: "pkg:pypi/d@1", Licenses: []string{strings.Repeat("x", 300)}},
	}
	got := NormalizeComponents(in)
	if len(got) != 2 || got[0].PURL != "pkg:pypi/a@1" || got[1].PURL != "pkg:pypi/b@1" {
		t.Fatalf("composants : %+v", got)
	}
	if !slices.Equal(got[1].Licenses, []string{"Apache-2.0", "MIT"}) {
		t.Fatalf("licences : %v", got[1].Licenses)
	}
	// L'ordre d'entrée ne change pas l'empreinte.
	rev := slices.Clone(in)
	slices.Reverse(rev)
	if Fingerprint(NormalizeComponents(rev)) != Fingerprint(got) {
		t.Fatal("l'empreinte dépend de l'ordre des composants")
	}
	if Fingerprint(got) == Fingerprint(got[:1]) {
		t.Fatal("deux listes différentes ont la même empreinte")
	}
}

func TestCheckSBOMs(t *testing.T) {
	cs := NormalizeComponents([]Component{{PURL: "pkg:pypi/a@1"}})
	s := &Snapshot{SBOMs: []SBOM{
		{Digest: "sha256:" + strings.Repeat("a", 64), Fingerprint: Fingerprint(cs), Components: cs},
		{Digest: "sha256:" + strings.Repeat("b", 64), Fingerprint: Fingerprint(nil), Components: cs},
	}}
	if n := s.CheckSBOMs(); n != 1 || len(s.SBOMs) != 1 || s.SBOMs[0].Digest[7] != 'a' {
		t.Fatalf("écartés %d, restants %+v", n, s.SBOMs)
	}
}

func TestValidateInventory(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	s := Snapshot{Workloads: []Workload{}, Reports: []VulnerabilityReport{}, Inventory: []ImageSBOM{{Digest: d, Fingerprint: d}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Inventory[0].Fingerprint = "md5:x"
	if err := s.Validate(); err == nil {
		t.Fatal("une empreinte invalide doit être refusée")
	}
}

func TestSBOMUpload(t *testing.T) {
	cs := NormalizeComponents([]Component{{PURL: "pkg:deb/debian/openssl@3.0.15", Type: "debian"}})
	good := SBOM{Digest: "sha256:" + strings.Repeat("a", 64), Fingerprint: Fingerprint(cs), Components: cs}
	if err := (&SBOMUpload{Version: SnapshotVersion, SBOMs: []SBOM{good}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&SBOMUpload{Version: SnapshotVersion, SBOMs: []SBOM{{Digest: "sha256:court", Fingerprint: good.Fingerprint}}}).Validate(); err == nil {
		t.Fatal("digest invalide accepté")
	}
	// Une empreinte qui ne correspond pas est écartée, le reste gardé.
	bad := good
	bad.Components = nil
	up := &SBOMUpload{SBOMs: []SBOM{bad, good}}
	if n := up.CheckSBOMs(); n != 1 || len(up.SBOMs) != 1 {
		t.Fatalf("écartés : %d, gardés : %+v", n, up.SBOMs)
	}
}
