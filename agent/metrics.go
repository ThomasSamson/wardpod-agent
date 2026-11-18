package agent

import (
	"net/http"

	"github.com/ThomasSamson/wardpod-agent/model"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	descSource = prometheus.NewDesc("wardpod_collect_source",
		"Source des vulnérabilités en service (1 pour la source active).", []string{"source"}, nil)
	descScannerImages = prometheus.NewDesc("wardpod_scanner_images",
		"Images en service suivies par le scanner intégré, par état.", []string{"state"}, nil)
	descScannerDBAge = prometheus.NewDesc("wardpod_scanner_db_age_seconds",
		"Âge de la base de vulnérabilités du scanner intégré.", nil, nil)
	descUnscannable = prometheus.NewDesc("wardpod_scanner_unscannable_images",
		"Images en service sans digest de registre (construites ou chargées sur le nœud) : impossibles à analyser.", nil, nil)
)

// MetricsCollector expose l'état de la collecte au format Prometheus.
func (s *Supervisor) MetricsCollector() prometheus.Collector { return supervisorMetrics{s} }

type supervisorMetrics struct{ s *Supervisor }

func (supervisorMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- descSource
	ch <- descScannerImages
	ch <- descScannerDBAge
	ch <- descUnscannable
}

func (m supervisorMetrics) Collect(ch chan<- prometheus.Metric) {
	s := m.s
	if cur := s.source.Load(); cur != nil {
		for _, name := range []string{model.SourceOperator, model.SourceBuiltin} {
			v := 0.0
			if name == *cur {
				v = 1
			}
			ch <- prometheus.MustNewConstMetric(descSource, prometheus.GaugeValue, v, name)
		}
	}
	st, ok := s.ScannerStatus()
	if !ok {
		return
	}
	for state, n := range map[string]int{"pending": st.Pending, "scanned": st.Scanned, "failed": st.Failed} {
		ch <- prometheus.MustNewConstMetric(descScannerImages, prometheus.GaugeValue, float64(n), state)
	}
	if c := s.collector.Load(); c != nil {
		if b, ok := c.source.(*BuiltinSource); ok {
			ch <- prometheus.MustNewConstMetric(descUnscannable, prometheus.GaugeValue, float64(b.Unscannable()))
		}
	}
	if st.DBAge > 0 {
		ch <- prometheus.MustNewConstMetric(descScannerDBAge, prometheus.GaugeValue, st.DBAge.Seconds())
	}
}

// Metrics sert les métriques de l'agent : collecte, scanner, processus.
func (s *Supervisor) Metrics() http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}), s.MetricsCollector())
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
