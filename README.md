# Agent Wardpod

L'agent de [Wardpod](https://wardpod.com) s'installe dans un cluster Kubernetes. Il lit le cluster **en lecture seule** et envoie à la console Wardpod ce qu'il faut pour prioriser les vulnérabilités : les workloads, leur exposition, leurs privilèges, les vulnérabilités et l'inventaire logiciel (SBOM) de leurs images.

Ce dépôt contient tout ce qui tourne dans votre cluster : le code de l'agent, son chart Helm et la construction de son image. Vous pouvez vérifier ce qui sort du cluster, reconstruire l'image vous-même et l'installer depuis vos propres registres. La console Wardpod (serveur, calcul du score, interface) est un service distinct, au code fermé.

## Ce que l'agent envoie

Un état complet du cluster, à intervalle régulier (`collect.interval`, 10 min par défaut) et après chaque rafale de changements. Le format est le contrat [`model.Snapshot`](model/snapshot.go) :

- **Workloads** : namespace, type, nom et propriétaire ; s'il tourne ; son exposition (internet, cluster, aucune) et les objets qui l'exposent (Service, Ingress, routes Gateway API et Traefik) ;
- **Conteneurs** : nom, image, et le résumé de leur `securityContext` (privilégié, espaces de noms de l'hôte, `hostPath`, root possible, élévation de privilèges, capacités dangereuses, système de fichiers en lecture seule, montage du jeton de compte de service) ;
- **Vulnérabilités** des images, par digest : identifiant (CVE…), paquet, version installée et corrigée, sévérité, score, lien, date de publication ;
- **Inventaire** (`collect.inventory`) : le SBOM CycloneDX de chaque image en service (paquets, versions, licences, purl) ;
- le nom du cluster, son environnement, la version de l'agent et le nom de son pod.

L'agent n'envoie **jamais** le contenu des images, ni celui des Secrets ou des ConfigMaps, ni les variables d'environnement des conteneurs. La seule exception : quelques variables de la configuration de l'**image** (`PHP_VERSION`, `NODE_VERSION`…, liste dans `scanner.runtimeEnv`), qui donnent la version d'un runtime compilé que trivy ne voit pas.

## Droits demandés

Un `ClusterRole` en lecture seule ([`templates/rbac.yaml`](charts/wardpod-agent/templates/rbac.yaml)) :

- `get`, `list` et `watch` sur les pods, services, replicationcontrollers, replicasets, daemonsets, statefulsets, jobs, cronjobs, ingresses, routes Gateway API et IngressRoutes Traefik ;
- les rapports du Trivy Operator (`vulnerabilityreports`, `sbomreports`) s'il est utilisé ;
- `create` sur `selfsubjectaccessreviews`, pour vérifier ses propres droits au démarrage.

Aucun droit d'écriture, aucun accès aux Secrets.

## Réseau

Une seule destination sortante : la console (`agent.serverURL`), en HTTPS, avec un certificat vérifié. Une adresse `http://` est refusée hors `localhost`, sauf avec `agent.allowInsecure`. Les redirections sont refusées, pour que le jeton ne parte jamais ailleurs.

Avec le scanner intégré, l'agent télécharge aussi la base de vulnérabilités de Trivy (ou vos miroirs : `scanner.dbRepository`) et tire les images de ses workloads depuis leurs registres, pour en faire le SBOM.

## Sources des vulnérabilités

`collect.source` :

- `auto` (par défaut) : le Trivy Operator s'il est installé et lisible, sinon le scanner intégré ;
- `operator` : uniquement les rapports du Trivy Operator. L'image allégée (`-slim`), sans trivy, suffit ;
- `builtin` : le scanner intégré analyse lui-même les images en service, une fois par digest. Les registres privés se déclarent par un Secret `dockerconfigjson` (`scanner.registryAuth`).

Avec `scanner.serverMatch`, l'agent ne fait que les SBOM, et la console y cherche les vulnérabilités. Il n'y a alors aucune base de vulnérabilités dans le cluster.

## Installation

Dans la console, « Ajouter un cluster » déclare le cluster et crée son jeton.

**Par la console** : elle donne une commande `kubectl apply` qui installe exactement le contenu de ce chart.

**Par Helm** :

```sh
kubectl create namespace wardpod
kubectl -n wardpod create secret generic wardpod-agent --from-literal=token=<jeton>
helm install wardpod-agent oci://ghcr.io/thomassamson/charts/wardpod-agent --version <version> -n wardpod \
  --set cluster.name=<nom du cluster> \
  --set agent.serverURL=<adresse de la console> \
  --set agent.existingSecret=wardpod-agent
```

Le jeton passe par un Secret créé à part : avec `--set`, il resterait dans l'historique du shell et dans les values de la release. Les values sont décrites dans [`values.yaml`](charts/wardpod-agent/values.yaml) et vérifiées par `values.schema.json` : une clé mal orthographiée est refusée.

Mise à jour : `helm upgrade wardpod-agent oci://ghcr.io/thomassamson/charts/wardpod-agent --version <version> -n wardpod --reuse-values`.

## Vérifier les images et le chart

Images et chart sont signés par cosign avec la clé du projet ([`cosign.pub`](cosign.pub)) :

```sh
cosign verify --key cosign.pub docker.io/thomassamson33/wardpod-agent:<version>
cosign verify --key cosign.pub ghcr.io/thomassamson/charts/wardpod-agent:<version>
```

Chaque image porte son SBOM et sa provenance (attestations BuildKit), les licences de ses dépendances (`/usr/share/licenses/wardpod/THIRD_PARTY_LICENSES`) et celle de trivy.

## Configuration

Chaque réglage est une clé de [`config.example.yaml`](config.example.yaml), qui donne aussi sa valeur par défaut. Chaque clé est à la fois une variable d'environnement et un flag, déduits de son chemin : `collect.syncTimeout` donne `WP_COLLECT_SYNC_TIMEOUT` et `-collect.syncTimeout`. Un secret peut se lire depuis un fichier : `WP_AGENT_TOKEN_FILE`.

```sh
wardpod config -check agent                                   # configuration effective, secrets masqués
wardpod agent -dump -context <contexte kubectl> -cluster test # snapshot sur la sortie standard, rien n'est envoyé
```

Hors du cluster, l'agent exige un contexte explicite et ne prend jamais le contexte courant.

## Développement

```sh
mise install        # Go, helm, kubeconform aux versions épinglées
make lint test      # gofmt, go vet, tests (dont envtest et le chart)
make build          # bin/wardpod
make image          # images locales (Docker)
```

| Chemin | Rôle |
|---|---|
| `model` | contrat agent → console (`Snapshot`). Toute rupture incrémente `SnapshotVersion`. |
| `agent` | collecte : informers, exposition et `securityContext`, sources des vulnérabilités, envoi, boucle, sondes. |
| `scanner` | scanner intégré : pilote `trivy` (SBOM par digest en cache, recherche sur le SBOM). |
| `config` | configuration : défauts, YAML facultatif (`WP_CONFIG`), variables `WP_*`, flags. |
| `charts/wardpod-agent` | chart Helm, identique au manifeste donné par la console. |

## Contributions et sécurité

Les issues sont ouvertes, et les contributions sont acceptées à la discrétion de l'éditeur, sans engagement de support : voir [CONTRIBUTING.md](CONTRIBUTING.md). Pour signaler une faille, voir [SECURITY.md](SECURITY.md).

## Licence

[Apache 2.0](LICENSE).
