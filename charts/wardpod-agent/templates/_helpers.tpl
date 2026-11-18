{{/* Nom complet des ressources, borné à 63 caractères. Les ressources
portent les mêmes noms que celles de la commande d'installation de la
console (release wardpod). */}}
{{- define "psa.fullname" -}}
{{- if contains "wardpod" .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-wardpod" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Sélecteur identique à celui de la commande d'installation : passer de
l'une à l'autre ne recrée pas le Deployment. */}}
{{- define "psa.selectorLabels" -}}
app.kubernetes.io/name: wardpod
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end -}}

{{- define "psa.labels" -}}
{{ include "psa.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/* Image : <tag> avec le scanner intégré, <tag>-slim pour la source
operator. */}}
{{- define "psa.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{ if eq .Values.collect.source "operator" }}-slim{{ end }}
{{- end -}}
{{- end -}}

{{/* Ressources sans namespace : le namespace entre dans le nom. */}}
{{- define "psa.clusterName" -}}
{{- printf "%s-%s" (include "psa.fullname" .) .Release.Namespace | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "psa.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ default (include "psa.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{- define "psa.secretName" -}}
{{ default (printf "%s-agent" (include "psa.fullname" .)) .Values.agent.existingSecret }}
{{- end -}}

{{- define "psa.claimName" -}}
{{ default (printf "%s-scanner-cache" (include "psa.fullname" .)) .Values.scanner.cache.persistence.existingClaim }}
{{- end -}}

{{/* Contrôles de cohérence des values. */}}
{{- define "psa.validate" -}}
{{- if not .Values.cluster.name -}}
{{- fail "cluster.name est obligatoire : le nom du cluster déclaré dans la console" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$" .Values.cluster.name) -}}
{{- fail (printf "cluster.name %q invalide : minuscules, chiffres et tirets, 63 caractères au plus" .Values.cluster.name) -}}
{{- end -}}
{{- if not (has .Values.collect.source (list "auto" "operator" "builtin")) -}}
{{- fail (printf "collect.source doit valoir auto, operator ou builtin (%q)" .Values.collect.source) -}}
{{- end -}}
{{- if and .Values.scanner.serverMatch (not .Values.collect.inventory) -}}
{{- fail "scanner.serverMatch exige collect.inventory : les SBOM complets partent avec ceux de l'inventaire" -}}
{{- end -}}
{{- if not .Values.agent.serverURL -}}
{{- fail "agent.serverURL est obligatoire : l'adresse du service Wardpod" -}}
{{- end -}}
{{- if and (hasPrefix "http://" .Values.agent.serverURL) (not .Values.agent.allowInsecure) -}}
{{- fail "agent.serverURL en http:// : le jeton circulerait en clair ; utiliser https:// ou agent.allowInsecure=true" -}}
{{- end -}}
{{- if not (or (hasPrefix "https://" .Values.agent.serverURL) (hasPrefix "http://" .Values.agent.serverURL)) -}}
{{- fail "agent.serverURL doit commencer par https://" -}}
{{- end -}}
{{- if not (or .Values.agent.token .Values.agent.existingSecret) -}}
{{- fail "fournir le jeton du cluster par agent.existingSecret (ou agent.token)" -}}
{{- end -}}
{{- /* Variables réglées par le chart, et secrets : ces derniers passent par
     des Secrets, jamais par la ConfigMap. */ -}}
{{- $managed := list "WP_LOG_LEVEL" "WP_LOG_FORMAT" "WP_SHUTDOWN_TIMEOUT" "WP_COLLECT_CLUSTER" "WP_COLLECT_ENVIRONMENT" "WP_COLLECT_SOURCE" "WP_COLLECT_INTERNAL_GATEWAYS" "WP_COLLECT_INTERNAL_GATEWAY_CLASSES" "WP_COLLECT_INVENTORY" "WP_SCANNER_CACHE_DIR" "WP_AGENT_SERVER_URL" "WP_AGENT_ALLOW_INSECURE" "WP_AGENT_LISTEN" -}}
{{- $secrets := list "WP_AGENT_TOKEN" "WP_SCANNER_REGISTRY_AUTH" -}}
{{- range $k, $v := .Values.env -}}
{{- if not (hasPrefix "WP_" $k) -}}
{{- fail (printf "env.%s : seules les variables WP_* sont acceptées" $k) -}}
{{- end -}}
{{- if has $k $managed -}}
{{- fail (printf "env.%s : variable réglée par le chart, utiliser la value dédiée (log, shutdownTimeoutSeconds, cluster, collect, agent)" $k) -}}
{{- end -}}
{{- if or (has $k $secrets) (hasSuffix "_FILE" $k) -}}
{{- fail (printf "env.%s : secret, à fournir par un Secret (agent.existingSecret, scanner.registryAuth.existingSecret), jamais en clair dans une ConfigMap" $k) -}}
{{- end -}}
{{- end -}}
{{- end -}}
