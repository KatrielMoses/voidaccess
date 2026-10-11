#!/usr/bin/env bash
#
# migrate-to-vps.sh — one-command migration of a VoidAccess deployment to another
# Docker host (paid VPS fallback for the Oracle Always Free box; see
# docs/deploy-oracle.md). No provider lock-in: the target is any host with SSH +
# Docker.
#
# It bundles the state that is NOT in git — .env and the Docker named volumes
# (Postgres data OR the SQLite file, Chroma vectors, monitors/seeds, Tor keys) —
# ships repo + bundle over SSH, restores, and brings the stack up. Because state
# (including any QUEUED jobs) travels along, the new host resumes in-flight work
# rather than dropping it.
#
# Usage:
#   scripts/migrate-to-vps.sh user@target-host [--sqlite] [--dir /remote/path]
#
#   --sqlite      Postgres-less mode: carry the SQLite file (in monitors_data)
#                 instead of a Postgres dump.
#   --dir PATH    Remote install dir (default: ~/VoidAccess/voidaccess).
#
# Prereqs: SSH key access to the target; Docker + docker compose plugin on the
# target; run from the voidaccess/ directory of the source host.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 user@target-host [--sqlite] [--dir /remote/path]" >&2
  exit 2
fi

TARGET="$1"; shift
SQLITE=0
DRY_RUN=0
REMOTE_DIR="~/VoidAccess/voidaccess"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sqlite) SQLITE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --dir) REMOTE_DIR="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null || { echo "docker not found on source host" >&2; exit 1; }
[[ -f docker-compose.yml && -f .env ]] || { echo "run from voidaccess/ (needs docker-compose.yml and .env)" >&2; exit 1; }

BUNDLE="$(mktemp -d)/voidaccess-state.tar.gz"
# meili_data carries the P3.0 owned index; omitting it would migrate the stack
# but silently drop the owned search index (and leave queued freshness/index
# jobs pointing at an empty index on the new host).
VOLUMES=(chroma_data monitors_data tor_data meili_data)
[[ "$SQLITE" -eq 0 ]] && VOLUMES+=(postgres_data)

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[migrate] DRY RUN — no stack stop, no SSH, no changes."
  echo "  target      : ${TARGET}"
  echo "  remote dir  : ${REMOTE_DIR}"
  echo "  mode        : $([[ $SQLITE -eq 1 ]] && echo SQLite || echo Postgres)"
  echo "  volumes     : ${VOLUMES[*]}"
  echo "  carries     : .env + named volumes above (incl. Postgres/SQLite state → QUEUED jobs travel)"
  echo "  would rsync : repo (excluding .git/node_modules/.next) → ${TARGET}:${REMOTE_DIR}"
  exit 0
fi

echo "[migrate] Quiescing the stack (stop, no data loss)…"
docker compose stop

echo "[migrate] Bundling .env + volumes: ${VOLUMES[*]}"
# Prefix volume names with the compose project (directory name) as Docker does.
PROJECT="$(basename "$(pwd)" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
TMP_VOL="$(mktemp -d)"
for v in "${VOLUMES[@]}"; do
  full="${PROJECT}_${v}"
  if docker volume inspect "$full" >/dev/null 2>&1; then
    docker run --rm -v "${full}:/from" -v "${TMP_VOL}:/to" alpine \
      sh -c "cd /from && tar czf /to/${v}.tar.gz ."
  else
    echo "[migrate]   (volume ${full} not present — skipping)"
  fi
done
cp .env "${TMP_VOL}/.env.bundle"
tar czf "$BUNDLE" -C "$TMP_VOL" .

echo "[migrate] Syncing repo + state to ${TARGET}:${REMOTE_DIR}"
ssh "$TARGET" "mkdir -p ${REMOTE_DIR}"
rsync -az --exclude '.git' --exclude 'node_modules' --exclude '.next' ./ "${TARGET}:${REMOTE_DIR}/"
scp "$BUNDLE" "${TARGET}:${REMOTE_DIR}/voidaccess-state.tar.gz"

echo "[migrate] Restoring + starting on target"
ssh "$TARGET" bash -s -- "$REMOTE_DIR" "$PROJECT" "${VOLUMES[*]}" <<'REMOTE'
set -euo pipefail
DIR="$1"; PROJECT="$2"; read -r -a VOLS <<< "$3"
cd "$DIR"
mkdir -p _restore && tar xzf voidaccess-state.tar.gz -C _restore
[[ -f _restore/.env.bundle ]] && cp _restore/.env.bundle .env
docker compose up -d --build postgres tor >/dev/null 2>&1 || true
for v in "${VOLS[@]}"; do
  full="${PROJECT}_${v}"
  [[ -f "_restore/${v}.tar.gz" ]] || continue
  docker volume create "$full" >/dev/null
  docker run --rm -v "${full}:/to" -v "$(pwd)/_restore:/from" alpine \
    sh -c "cd /to && tar xzf /from/${v}.tar.gz"
done
rm -rf _restore voidaccess-state.tar.gz
docker compose up -d --build
echo "[migrate] Target stack is up. Check: curl -fsS http://localhost:8000/health"
REMOTE

echo "[migrate] Done. Bring the old host down once you've verified the target."
