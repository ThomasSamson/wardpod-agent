# Agent Wardpod : construction, contrôles et tests. Go, helm et kubeconform
# viennent de mise (mise install) ; govulncheck et setup-envtest sont
# épinglés dans go.mod (directive tool).

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null)
PKG     := github.com/ThomasSamson/wardpod-agent/version
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT)
CHART   := charts/wardpod-agent
ENVTEST_K8S_VERSION ?= 1.37.0
ENVTEST_DIR ?= $(CURDIR)/bin/envtest
KUBERNETES_VERSION ?= 1.34.0
# Schéma du PodMonitor pour kubeconform, catalogue épinglé par SHA de commit.
CRD_SCHEMAS ?= https://raw.githubusercontent.com/datreeio/CRDs-catalog/d373c2da9702bc9509a004db83e57263fe3bdfc1/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json
# helm-unittest épinglé par SHA de commit.
HELM_UNITTEST_VERSION ?= 67056cc631eab9e001e6762a1f601e6c92a71ba7

.PHONY: all build lint vuln test test-unit test-integration chart-lint chart-test chart-package image

all: lint test

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/wardpod .

lint:
	@test -z "$$(gofmt -l .)" || (echo "fichiers mal formatés :"; gofmt -l .; exit 1)
	go vet ./...

vuln:
	go tool govulncheck ./...

test: test-unit test-integration chart-lint chart-test

test-unit:
	go test -race ./...

# Tests contre un vrai kube-apiserver (envtest), sans cluster ni Docker, et
# concordance du chart avec le binaire. REQUIRE_* transforme un test ignoré
# faute d'outil en échec.
test-integration:
	@mkdir -p $(ENVTEST_DIR)
	assets="$$(go tool setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_DIR) -p path)" && test -n "$$assets" && \
		KUBEBUILDER_ASSETS="$$assets" REQUIRE_ENVTEST=1 REQUIRE_HELM=1 \
		go test -race -count=1 -run 'Integration|RunAgent|Chart' ./...

chart-lint:
	helm lint --strict $(CHART) -f $(CHART)/ci/operator-values.yaml
	@set -e; for f in $(CHART)/ci/*-values.yaml; do \
		echo "== $$f"; \
		out=$$(helm template wardpod $(CHART) -f $$f); \
		test -n "$$out" || { echo "rendu vide"; exit 1; }; \
		echo "$$out" | kubeconform -strict -summary -kubernetes-version $(KUBERNETES_VERSION) \
			-schema-location default -schema-location '$(CRD_SCHEMAS)' -; \
	done
	@set -e; for f in $(CHART)/tests/fail/*-values.yaml; do \
		want=$$(sed -n '1s/^# erreur : //p' $$f); \
		test -n "$$want" || { echo "$$f : première ligne « # erreur : <message attendu> » manquante"; exit 1; }; \
		if out=$$(helm template wardpod $(CHART) -f $$f 2>&1); then echo "accepté à tort : $$f"; exit 1; fi; \
		echo "$$out" | grep -qF "$$want" || { echo "$$f : erreur inattendue : $$out"; exit 1; }; \
		echo "refusé comme attendu : $$f"; \
	done

chart-test:
	@helm plugin list | grep -q '^unittest' || helm plugin install https://github.com/helm-unittest/helm-unittest.git --version $(HELM_UNITTEST_VERSION) --verify=false
	helm unittest $(CHART)

# Archive du chart dans dist/, à la version de l'agent (VERSION=v0.8.35).
chart-package:
	helm package $(CHART) --version $(patsubst v%,%,$(VERSION)) --app-version $(patsubst v%,%,$(VERSION)) -d dist

# Images locales : avec le scanner intégré, et -slim sans trivy.
image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --target agent -t wardpod-agent:$(VERSION) .
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --target agent-slim -t wardpod-agent:$(VERSION)-slim .
