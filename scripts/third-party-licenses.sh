#!/bin/sh
# Licences des dépendances livrées dans le binaire de l'agent Wardpod : texte de la
# licence de chaque dépendance, et son NOTICE s'il en a un. Le Dockerfile
# assemble les parties dans /usr/share/licenses/wardpod/THIRD_PARTY_LICENSES.
#
#   scripts/third-party-licenses.sh go   # modules Go (depuis la racine du dépôt)
#
# Exige go-licenses (github.com/google/go-licenses/v2) et le cache des
# modules.
set -eu

# section <nom> <licence> <fichier de licence>
section() {
	printf '================================================================================\n%s (%s)\n================================================================================\n\n' "$1" "$2"
	cat "$3"
	notice=$(dirname "$3")/NOTICE
	if [ -f "$notice" ]; then
		printf '\n--- NOTICE ---\n\n'
		cat "$notice"
	fi
	printf '\n\n'
}

case "${1:-}" in
go)
	template=$(mktemp)
	trap 'rm -f "$template"' EXIT
	printf '{{range .}}{{.Name}}|{{.LicenseName}}|{{.LicensePath}}\n{{end}}' >"$template"
	# Un module fournit souvent plusieurs paquets : une section par fichier
	# de licence. Le code de l'agent lui-même est ignoré.
	go-licenses report . --ignore github.com/ThomasSamson/wardpod-agent --template "$template" 2>/dev/null |
		sort -t'|' -k3,3 -u | sort |
		while IFS='|' read -r name license path; do
			[ -n "$name" ] || continue
			if [ ! -f "$path" ]; then
				echo "licence introuvable pour $name" >&2
				exit 1
			fi
			section "$name" "$license" "$path"
		done
	;;
*)
	echo "usage : $0 go" >&2
	exit 2
	;;
esac
