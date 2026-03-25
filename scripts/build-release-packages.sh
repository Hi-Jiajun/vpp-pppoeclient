#!/usr/bin/env bash
set -euo pipefail

SHORT_SHA=""
FULL_SHA=""
UPSTREAM_BRANCH="feat/pr-pppoeclient"
OUTPUT_DIR="dist"
PACKAGE_NAME="vpp-pppoeclient-source"

usage() {
  cat <<'EOF'
Usage: scripts/build-release-packages.sh [options]

Options:
  --short-sha <sha>         Short commit SHA used in asset names
  --full-sha <sha>          Full commit SHA recorded in package docs
  --upstream-branch <name>  Upstream branch name recorded in package docs
  --output-dir <dir>        Output directory for built assets (default: dist)
  -h, --help                Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --short-sha)
      SHORT_SHA="$2"
      shift 2
      ;;
    --full-sha)
      FULL_SHA="$2"
      shift 2
      ;;
    --upstream-branch)
      UPSTREAM_BRANCH="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
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
require_cmd zip
require_cmd fpm

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -z "${FULL_SHA}" ]]; then
  FULL_SHA="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
fi

if [[ -z "${SHORT_SHA}" ]]; then
  SHORT_SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
fi

VERSION_DATE="$(date -u +'%Y.%m.%d')"
PACKAGE_VERSION="${VERSION_DATE}"
PACKAGE_ITERATION="git${SHORT_SHA}"

ZIP_ASSET_NAME="vpp-pppoeclient-${SHORT_SHA}.zip"
DEB_ASSET_NAME="${PACKAGE_NAME}_${PACKAGE_VERSION}-${PACKAGE_ITERATION}_all.deb"
RPM_ASSET_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}-${PACKAGE_ITERATION}.noarch.rpm"

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

ARCHIVE_ROOT="${OUTPUT_DIR}/archive-root"
PACKAGE_ROOT="${OUTPUT_DIR}/package-root"
SHARE_ROOT="${PACKAGE_ROOT}/usr/share/vpp-pppoeclient"

mkdir -p "${ARCHIVE_ROOT}/src/plugins"
mkdir -p "${SHARE_ROOT}/src/plugins"

cp -R "${REPO_ROOT}/src/plugins/pppoeclient" "${ARCHIVE_ROOT}/src/plugins/"
cp -R "${REPO_ROOT}/src/plugins/pppox" "${ARCHIVE_ROOT}/src/plugins/"
cp "${REPO_ROOT}/LICENSE" "${ARCHIVE_ROOT}/"

cp -R "${REPO_ROOT}/src/plugins/pppoeclient" "${SHARE_ROOT}/src/plugins/"
cp -R "${REPO_ROOT}/src/plugins/pppox" "${SHARE_ROOT}/src/plugins/"
cp "${REPO_ROOT}/LICENSE" "${SHARE_ROOT}/"

cat > "${ARCHIVE_ROOT}/README.md" <<EOF
# VPP PPPoE Client Release Package

This archive contains only the files needed to integrate the PPPoE client plugins into a VPP source tree:

- src/plugins/pppoeclient
- src/plugins/pppox
- LICENSE

Source repository:
- https://github.com/Hi-Jiajun/vpp-pppoeclient

Source commit:
- ${FULL_SHA}

Upstream branch:
- ${UPSTREAM_BRANCH}

Usage:
1. Copy \`src/plugins/pppoeclient\` into your VPP source tree under \`src/plugins/\`
2. Copy \`src/plugins/pppox\` into your VPP source tree under \`src/plugins/\`
3. Build the plugins in your VPP tree, for example:

   \`\`\`bash
   ninja -C build-root/build-vpp-native/vpp pppox_plugin pppoeclient_plugin vpp vppctl
   \`\`\`

Notes:
- This package intentionally excludes repository automation files and extra docs not required for VPP integration
- Debian/RPM packages install the same payload under \`/usr/share/vpp-pppoeclient/\`
EOF

cp "${ARCHIVE_ROOT}/README.md" "${SHARE_ROOT}/README.md"

(
  cd "${ARCHIVE_ROOT}"
  zip -qr "../${ZIP_ASSET_NAME}" .
)

fpm \
  -s dir \
  -t deb \
  -n "${PACKAGE_NAME}" \
  -v "${PACKAGE_VERSION}" \
  --iteration "${PACKAGE_ITERATION}" \
  -a all \
  --description "Source integration package for the VPP PPPoE client plugins" \
  --url "https://github.com/Hi-Jiajun/vpp-pppoeclient" \
  --license "Apache-2.0" \
  --maintainer "Hi-Jiajun" \
  --package "${OUTPUT_DIR}/${DEB_ASSET_NAME}" \
  -C "${PACKAGE_ROOT}" \
  .

fpm \
  -s dir \
  -t rpm \
  -n "${PACKAGE_NAME}" \
  -v "${PACKAGE_VERSION}" \
  --iteration "${PACKAGE_ITERATION}" \
  -a noarch \
  --description "Source integration package for the VPP PPPoE client plugins" \
  --url "https://github.com/Hi-Jiajun/vpp-pppoeclient" \
  --license "Apache-2.0" \
  --maintainer "Hi-Jiajun" \
  --package "${OUTPUT_DIR}/${RPM_ASSET_NAME}" \
  -C "${PACKAGE_ROOT}" \
  .

echo "Built assets:"
echo "  ${OUTPUT_DIR}/${ZIP_ASSET_NAME}"
echo "  ${OUTPUT_DIR}/${DEB_ASSET_NAME}"
echo "  ${OUTPUT_DIR}/${RPM_ASSET_NAME}"
