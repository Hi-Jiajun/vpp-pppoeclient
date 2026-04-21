#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${1:-https://github.com/FDio/vpp.git}"

if ! command -v git >/dev/null 2>&1; then
  echo "git is required" >&2
  exit 1
fi

latest_tag="$(
  git ls-remote --tags "${REPO_URL}" \
    | awk '{print $2}' \
    | sed 's#refs/tags/##' \
    | sed 's/\^{}//' \
    | grep -E '^v[0-9]+\.[0-9]+(\.[0-9]+)?$' \
    | sort -uV \
    | tail -n 1
)"

if [[ -z "${latest_tag}" ]]; then
  echo "failed to detect latest stable tag from ${REPO_URL}" >&2
  exit 1
fi

echo "${latest_tag}"
