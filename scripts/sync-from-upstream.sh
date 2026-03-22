#!/usr/bin/env bash
set -euo pipefail

REMOTE_NAME="upstream"
REMOTE_URL="https://github.com/Hi-Jiajun/vpp.git"
BRANCH="feat/pr-pppoeclient"
CHECK_ONLY=0
KEEP_TEMP=0

PLUGIN_DIRS=(
  "src/plugins/pppoeclient"
  "src/plugins/pppox"
)

usage() {
  cat <<'EOF'
Usage: scripts/sync-from-upstream.sh [options]

Options:
  --remote-name <name>   Git remote name to use (default: upstream)
  --remote-url <url>     Git remote URL to use when adding the remote
  --branch <name>        Upstream branch to sync from (default: feat/pr-pppoeclient)
  --check                Check whether local plugin directories match upstream without modifying files
  --keep-temp            Keep the temporary sparse clone directory
  -h, --help             Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote-name)
      REMOTE_NAME="$2"
      shift 2
      ;;
    --remote-url)
      REMOTE_URL="$2"
      shift 2
      ;;
    --branch)
      BRANCH="$2"
      shift 2
      ;;
    --check)
      CHECK_ONLY=1
      shift
      ;;
    --keep-temp)
      KEEP_TEMP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

require_cmd git
require_cmd rsync

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! git -C "${REPO_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Repository root is not a git repository: ${REPO_ROOT}" >&2
  exit 1
fi

if ! git -C "${REPO_ROOT}" remote | grep -Fxq "${REMOTE_NAME}"; then
  echo "Adding remote '${REMOTE_NAME}' -> ${REMOTE_URL}"
  git -C "${REPO_ROOT}" remote add "${REMOTE_NAME}" "${REMOTE_URL}"
fi

RESOLVED_REMOTE_URL="$(git -C "${REPO_ROOT}" remote get-url "${REMOTE_NAME}")"

echo "Fetching ${REMOTE_NAME}/${BRANCH} ..."
git -C "${REPO_ROOT}" fetch "${REMOTE_NAME}" "${BRANCH}"

UPSTREAM_COMMIT="$(git -C "${REPO_ROOT}" rev-parse "${REMOTE_NAME}/${BRANCH}")"

if [[ "${CHECK_ONLY}" -eq 1 ]]; then
  echo "Checking tracked plugin directories against ${REMOTE_NAME}/${BRANCH}"
  if git -C "${REPO_ROOT}" diff --quiet HEAD "${REMOTE_NAME}/${BRANCH}" -- "${PLUGIN_DIRS[@]}"; then
    echo
    echo "Check complete."
    echo "Upstream branch: ${BRANCH}"
    echo "Upstream commit: ${UPSTREAM_COMMIT}"
    echo "Result: tracked plugin directories are in sync with upstream."
    exit 0
  fi

  echo
  echo "Out of sync with upstream:"
  git -C "${REPO_ROOT}" diff --stat HEAD "${REMOTE_NAME}/${BRANCH}" -- "${PLUGIN_DIRS[@]}" || true
  echo
  echo "Check complete."
  echo "Upstream branch: ${BRANCH}"
  echo "Upstream commit: ${UPSTREAM_COMMIT}"
  echo "Result: tracked plugin directories are NOT in sync with upstream." >&2
  exit 1
fi

TEMP_CLONE="$(mktemp -d "${TMPDIR:-/tmp}/vpp-plugin-sync.XXXXXX")"

cleanup() {
  if [[ "${KEEP_TEMP}" -eq 0 && -d "${TEMP_CLONE}" ]]; then
    rm -rf "${TEMP_CLONE}"
  fi
}
trap cleanup EXIT

echo "Creating sparse clone in ${TEMP_CLONE}"
git clone --depth 1 --filter=blob:none --sparse --branch "${BRANCH}" "${RESOLVED_REMOTE_URL}" "${TEMP_CLONE}"

echo "Checking out plugin directories only"
git -C "${TEMP_CLONE}" sparse-checkout set "${PLUGIN_DIRS[@]}"

UPSTREAM_COMMIT="$(git -C "${TEMP_CLONE}" rev-parse HEAD)"

for dir in "${PLUGIN_DIRS[@]}"; do
  SRC="${TEMP_CLONE}/${dir}"
  DST="${REPO_ROOT}/${dir}"
  echo "Syncing ${dir}"
  rsync -a --delete "${SRC}/" "${DST}/"
done

echo
echo "Sync complete."
echo "Upstream branch: ${BRANCH}"
echo "Upstream commit: ${UPSTREAM_COMMIT}"
echo
echo "Next suggested commands:"
echo "  git status --short"
echo "  git diff --stat"
