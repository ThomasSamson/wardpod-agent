# Contribuer

Les issues sont ouvertes : signalements de bugs, questions sur ce que collecte l'agent, demandes d'évolution. Les pull requests sont les bienvenues ; elles sont acceptées à la discrétion de l'éditeur de Wardpod, sans engagement de délai ni de support.

Avant d'ouvrir une pull request :

- `make lint test` passe ;
- le code, les commentaires, les messages de log et d'erreur sont en français, les identifiants en anglais ;
- un réglage nouveau est une clé de `config` : sa valeur par défaut dans `Default…()`, sa documentation dans `config.example.yaml` (`TestExampleMatchesDefaults`), et une value du chart avec son schéma (`values.schema.json`) ;
- toute rupture du contrat `model.Snapshot` incrémente `SnapshotVersion` ; un champ ajouté sans rupture est facultatif (`omitempty`) ;
- l'agent reste en lecture seule sur le cluster : aucun droit d'écriture, aucun accès aux Secrets.

En proposant une contribution, vous acceptez qu'elle soit publiée sous la licence du dépôt (Apache 2.0).
