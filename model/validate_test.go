package model

import (
	"errors"
	"strings"
	"testing"
)

func valid() *Snapshot {
	return &Snapshot{
		Version: 1, Cluster: "c1",
		Workloads: []Workload{{Namespace: "ns", Kind: "Pod", Name: "p", Exposure: ExposureCluster}},
		Reports: []VulnerabilityReport{{Namespace: "ns", WorkloadKind: "Pod", WorkloadName: "p",
			Vulnerabilities: []Vulnerability{{ID: "CVE-1", Package: "a", Score: 7.5, PrimaryLink: "https://avd.aquasec.com/nvd/cve-1"}}}},
	}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	empty := &Snapshot{Version: 1, Workloads: []Workload{}, Reports: []VulnerabilityReport{}}
	if err := empty.Validate(); err != nil {
		t.Fatalf("snapshot vide : %v", err)
	}
	for name, mutate := range map[string]func(*Snapshot){
		"reports absent":    func(s *Snapshot) { s.Reports = nil },
		"workloads absent":  func(s *Snapshot) { s.Workloads = nil },
		"source inconnue":   func(s *Snapshot) { s.Source = "autre" },
		"exposition":        func(s *Snapshot) { s.Workloads[0].Exposure = "galaxie" },
		"octet nul":         func(s *Snapshot) { s.Reports[0].Vulnerabilities[0].Title = "a\x00b" },
		"CVE vide":          func(s *Snapshot) { s.Reports[0].Vulnerabilities[0].ID = "" },
		"CVSS négatif":      func(s *Snapshot) { s.Reports[0].Vulnerabilities[0].Score = -1 },
		"CVSS trop grand":   func(s *Snapshot) { s.Reports[0].Vulnerabilities[0].Score = 11 },
		"environnement":     func(s *Snapshot) { s.Environment = strings.Repeat("x", 400000) },
		"workload sans nom": func(s *Snapshot) { s.Workloads[0].Name = "" },
	} {
		s := valid()
		mutate(s)
		if err := s.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
			t.Errorf("%s : %v", name, err)
		}
	}
	s := valid()
	s.Reports[0].Vulnerabilities[0].PrimaryLink = "javascript:alert(1)"
	if err := s.Validate(); err != nil || s.Reports[0].Vulnerabilities[0].PrimaryLink != "" {
		t.Fatalf("lien dangereux : %v %q", err, s.Reports[0].Vulnerabilities[0].PrimaryLink)
	}
	// Beaucoup d'erreurs : le message reste borné.
	s = valid()
	for range 100 {
		s.Workloads = append(s.Workloads, Workload{})
	}
	if err := s.Validate(); err == nil || strings.Count(err.Error(), "\n") > 25 {
		t.Fatalf("erreurs non bornées : %v", err)
	}
}

// Une vulnérabilité hostile est écartée sans faire refuser le snapshot.
func TestDropInvalidVulnerabilities(t *testing.T) {
	s := valid()
	s.Reports[0].Vulnerabilities = append(s.Reports[0].Vulnerabilities,
		Vulnerability{ID: "CVE-X", InstalledVersion: strings.Repeat("9", 5000)},
		Vulnerability{ID: "CVE-Y", Package: "a\x00b"},
		Vulnerability{ID: "CVE-Z", Score: 42},
	)
	before := len(s.Reports[0].Vulnerabilities)
	if n := s.DropInvalidVulnerabilities(); n != 3 || len(s.Reports[0].Vulnerabilities) != before-3 {
		t.Fatalf("écartées : %d", n)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("snapshot refusé après nettoyage : %v", err)
	}
}
