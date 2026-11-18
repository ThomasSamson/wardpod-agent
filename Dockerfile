# Images de l'agent Wardpod : une version de code, des images immuables ; la
# configuration arrive à l'exécution par l'environnement. Les images de base
# sont épinglées par digest.
#   --target agent-slim : agent sans trivy, pour un cluster qui a le Trivy
#                         Operator ;
#   --target agent      : agent avec le scanner intégré (cible par défaut).

FROM --platform=$BUILDPLATFORM golang:1.26.11@sha256:4165ee6bf3b7811fd7b40373290405c83d0167dcb87ee5f29c427cdcef45ff8f AS src
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

FROM src AS build
ARG VERSION=dev
ARG COMMIT=
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/ThomasSamson/wardpod-agent/version.Version=${VERSION} -X github.com/ThomasSamson/wardpod-agent/version.Commit=${COMMIT}" \
      -o /out/wardpod .

# Licences des dépendances livrées, dans
# /usr/share/licenses/wardpod/THIRD_PARTY_LICENSES.
FROM src AS licenses
RUN go install github.com/google/go-licenses/v2@v2.0.1
RUN set -eu; mkdir -p /out; \
    { echo "Logiciels tiers inclus dans l'agent Wardpod et leurs licences."; echo; sh scripts/third-party-licenses.sh go; } > /out/THIRD_PARTY_LICENSES

# Binaire trivy du scanner intégré (utilisé quand le Trivy Operator est
# absent). Version et sommes de contrôle épinglées ensemble : pour monter de
# version, reprendre les deux sommes dans trivy_<version>_checksums.txt de
# la publication. Sa licence (Apache 2.0) accompagne le binaire.
FROM --platform=$BUILDPLATFORM golang:1.26.11@sha256:4165ee6bf3b7811fd7b40373290405c83d0167dcb87ee5f29c427cdcef45ff8f AS trivy
ARG TARGETARCH
RUN set -eu; v=0.76.1; \
    case "$TARGETARCH" in \
      amd64) a=64bit; sum=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0 ;; \
      arm64) a=ARM64; sum=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f ;; \
      *) echo "architecture non prise en charge : $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v$v/trivy_${v}_Linux-$a.tar.gz"; \
    echo "$sum  /tmp/trivy.tgz" | sha256sum -c -; \
    mkdir -p /out && tar -xzf /tmp/trivy.tgz -C /out trivy LICENSE

# Agent seul, pour un cluster qui a le Trivy Operator (collect.source
# operator) : environ 40 Mo.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS agent-slim
COPY --from=build /out/wardpod /usr/local/bin/wardpod
COPY --from=licenses /out/THIRD_PARTY_LICENSES /usr/share/licenses/wardpod/THIRD_PARTY_LICENSES
COPY LICENSE /usr/share/licenses/wardpod/LICENSE
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/wardpod"]

# Agent avec le scanner intégré (sources auto et builtin).
FROM agent-slim AS agent
COPY --from=trivy /out/trivy /usr/local/bin/trivy
COPY --from=trivy /out/LICENSE /usr/share/licenses/trivy/LICENSE
