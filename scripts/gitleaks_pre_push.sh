#!/usr/bin/env bash
# Scan Gitleaks des commits sortants d'une référence poussée.
#
# Pre-commit ou un hook git pre-push peut transmettre les 5 arguments :
# <ref locale> <SHA local> <ref distante> <SHA distant> <remote>
# ou fournir PRE_COMMIT_FROM_REF / PRE_COMMIT_TO_REF (et à défaut
# PRE_COMMIT_LOCAL_BRANCH et PRE_COMMIT_REMOTE_NAME).
#
# Échec (code de sortie non nul) => push bloqué.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
CONFIG="${REPO_ROOT}/.gitleaks.toml"
BASELINE="${REPO_ROOT}/.gitleaks-baseline.json"
ZERO_SHA="0000000000000000000000000000000000000000"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "erreur : gitleaks est introuvable dans le PATH." >&2
  echo "Installez gitleaks v8.30.1 : https://github.com/gitleaks/gitleaks/releases" >&2
  exit 1
fi

if [ "$#" -eq 5 ]; then
  LOCAL_REF="$1"
  LOCAL_SHA="$2"
  REMOTE_SHA="$4"
  REMOTE="$5"
elif [ "$#" -eq 0 ]; then
  LOCAL_REF="${PRE_COMMIT_LOCAL_BRANCH:-HEAD}"
  LOCAL_SHA="${PRE_COMMIT_TO_REF:-}"
  REMOTE_SHA="${PRE_COMMIT_FROM_REF:-}"
  REMOTE="${PRE_COMMIT_REMOTE_NAME:-origin}"
else
  echo "usage : $0 [<ref locale> <SHA local> <ref distante> <SHA distant> <remote>]" >&2
  exit 1
fi

# Suppression explicite de référence : aucun nouveau commit publié.
if [ "$LOCAL_SHA" = "$ZERO_SHA" ]; then
  exit 0
fi

# Si PRE_COMMIT_TO_REF n'est pas fourni (ex. push initial / branche orpheline
# ou exécution manuelle pre-push), résoudre la cible en SHA explicite (fail-closed).
if [ -z "$LOCAL_SHA" ]; then
  if [[ "$LOCAL_REF" == -* ]] || ! LOCAL_SHA="$(git rev-parse --verify "${LOCAL_REF}^{commit}" 2>/dev/null)"; then
    echo "erreur : impossible de résoudre la référence locale '${LOCAL_REF}'." >&2
    exit 1
  fi
fi

# Valider strictement le format SHA-1 (40 hex) pour prévenir toute injection d'option git.
if [[ ! "$LOCAL_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "erreur : SHA local invalide '${LOCAL_SHA}'." >&2
  exit 1
fi

if [ -n "$REMOTE_SHA" ] && [ "$REMOTE_SHA" != "$ZERO_SHA" ]; then
  if [[ ! "$REMOTE_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
    echo "erreur : SHA distant invalide '${REMOTE_SHA}'." >&2
    exit 1
  fi
  RANGE="${REMOTE_SHA}..${LOCAL_SHA}"
elif git remote get-url -- "${REMOTE}" >/dev/null 2>&1 && [[ ! "$REMOTE" =~ [[:space:]] ]]; then
  # Nouvelle branche ou nouveau tag : scanner les commits absents des refs de ce remote.
  RANGE="${LOCAL_SHA} --not --remotes=${REMOTE}"
else
  # Remote URL ou inconnu : scanner tout l'historique atteignable depuis LOCAL_SHA (fail-closed).
  RANGE="${LOCAL_SHA}"
fi

GITLEAKS_ARGS=(
  git
  # Inclure les patchs des commits de fusion, omis par défaut par git log.
  --log-opts="${RANGE} --diff-merges=first-parent"
  --config "${CONFIG}"
  --redact
  --verbose
)

if [ -f "${BASELINE}" ]; then
  GITLEAKS_ARGS+=(--baseline-path "${BASELINE}")
fi

gitleaks "${GITLEAKS_ARGS[@]}"
