#!/usr/bin/env bash
set -euo pipefail

VPP_REPO_URL="https://github.com/FDio/vpp.git"
VPP_REF="v26.02"
PACKAGE_TYPE=""
PACKAGE_ARCH=""
DISTRO_ID=""
PLUGIN_LIB_DIR=""
OUTPUT_DIR="dist"
SHORT_SHA=""
FULL_SHA=""
PACKAGE_NAME="vpp-pppoeclient-plugins"

usage() {
  cat <<'EOF'
Usage: scripts/build-binary-packages.sh [options]

Options:
  --vpp-repo-url <url>     Upstream VPP repository URL
  --vpp-ref <ref>          Stable VPP ref to build against
  --package-type <type>    deb or rpm
  --package-arch <arch>    Package architecture, for example amd64 or x86_64
  --distro-id <id>         Distro identifier used in asset names
  --plugin-lib-dir <path>  Final plugin install directory inside the package
  --output-dir <dir>       Output directory for built assets
  --short-sha <sha>        Short commit SHA for naming
  --full-sha <sha>         Full commit SHA recorded in docs
  -h, --help               Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vpp-repo-url)
      VPP_REPO_URL="$2"
      shift 2
      ;;
    --vpp-ref)
      VPP_REF="$2"
      shift 2
      ;;
    --package-type)
      PACKAGE_TYPE="$2"
      shift 2
      ;;
    --package-arch)
      PACKAGE_ARCH="$2"
      shift 2
      ;;
    --distro-id)
      DISTRO_ID="$2"
      shift 2
      ;;
    --plugin-lib-dir)
      PLUGIN_LIB_DIR="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --short-sha)
      SHORT_SHA="$2"
      shift 2
      ;;
    --full-sha)
      FULL_SHA="$2"
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

for cmd in git fpm find rsync make; do
  require_cmd "$cmd"
done

if [[ -z "${PACKAGE_TYPE}" || -z "${PACKAGE_ARCH}" || -z "${DISTRO_ID}" || -z "${PLUGIN_LIB_DIR}" ]]; then
  echo "Missing required packaging arguments" >&2
  usage >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -z "${FULL_SHA}" ]]; then
  FULL_SHA="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
fi

if [[ -z "${SHORT_SHA}" ]]; then
  SHORT_SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
fi

VPP_VERSION_RAW="${VPP_REF#v}"
VPP_VERSION="${VPP_VERSION_RAW%%-*}"
if [[ -z "${VPP_VERSION}" ]]; then
  VPP_VERSION="0.0"
fi

VPP_REF_SANITIZED="$(echo "${VPP_REF}" | sed 's/[^A-Za-z0-9._-]/-/g')"
ITERATION_SUFFIX="$(echo "${VPP_VERSION_RAW#${VPP_VERSION}}" | sed 's/^[.-]*//' | sed 's/[^A-Za-z0-9]/./g' | sed 's/\.\.+/./g' | sed 's/^\.//; s/\.$//')"
if [[ -n "${ITERATION_SUFFIX}" ]]; then
  PACKAGE_ITERATION="${ITERATION_SUFFIX}.git${SHORT_SHA}.${DISTRO_ID}"
else
  PACKAGE_ITERATION="git${SHORT_SHA}.${DISTRO_ID}"
fi

if [[ "${PACKAGE_TYPE}" == "deb" ]]; then
  ASSET_NAME="${PACKAGE_NAME}-${VPP_REF_SANITIZED}-${DISTRO_ID}.${PACKAGE_ARCH}.deb"
else
  ASSET_NAME="${PACKAGE_NAME}-${VPP_REF_SANITIZED}-${DISTRO_ID}.${PACKAGE_ARCH}.rpm"
fi

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/vpp-prebuilt.XXXXXX")"
trap 'rm -rf "${WORK_ROOT}"' EXIT

TOOLBIN="${WORK_ROOT}/toolbin"
VPP_WORKTREE="${WORK_ROOT}/vpp"
PKGROOT="${WORK_ROOT}/pkgroot"
DOCROOT="${PKGROOT}/usr/share/doc/${PACKAGE_NAME}"
APIDIR="${PKGROOT}/usr/share/vpp/api/plugins"
LIBROOT="${PKGROOT}${PLUGIN_LIB_DIR}"

mkdir -p "${TOOLBIN}"

if ! command -v sudo >/dev/null 2>&1; then
  cat > "${TOOLBIN}/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

args=("$@")
idx=0

while [[ ${idx} -lt ${#args[@]} ]]; do
  case "${args[$idx]}" in
    -E|-H|-n|-S|-k)
      idx=$((idx + 1))
      ;;
    --)
      idx=$((idx + 1))
      break
      ;;
    -*)
      idx=$((idx + 1))
      ;;
    *)
      break
      ;;
  esac
done

exec "${args[@]:$idx}"
EOF
  chmod +x "${TOOLBIN}/sudo"
  export PATH="${TOOLBIN}:${PATH}"
fi

echo "Cloning ${VPP_REPO_URL} at ${VPP_REF}"
git clone --depth 1 --branch "${VPP_REF}" "${VPP_REPO_URL}" "${VPP_WORKTREE}"

echo "Overlaying current plugin sources"
rsync -a --delete "${REPO_ROOT}/src/plugins/pppoeclient/" "${VPP_WORKTREE}/src/plugins/pppoeclient/"
rsync -a --delete "${REPO_ROOT}/src/plugins/pppox/" "${VPP_WORKTREE}/src/plugins/pppox/"

echo "Installing VPP build dependencies"
make -C "${VPP_WORKTREE}" UNATTENDED=y SUDO= install-dep

echo "Building plugin binaries against ${VPP_REF}"
make -C "${VPP_WORKTREE}" VPP_PLUGINS=pppoeclient,pppox build-release

PPPOECLIENT_SO="$(find "${VPP_WORKTREE}/build-root" -type f -name 'pppoeclient_plugin.so' | head -n 1)"
PPPOX_SO="$(find "${VPP_WORKTREE}/build-root" -type f -name 'pppox_plugin.so' | head -n 1)"
PPPOECLIENT_API_JSON="$(find "${VPP_WORKTREE}/build-root" -type f -path '*/share/vpp/api/plugins/pppoeclient.api.json' | head -n 1)"
PPPOX_API_JSON="$(find "${VPP_WORKTREE}/build-root" -type f -path '*/share/vpp/api/plugins/pppox.api.json' | head -n 1)"

for path in "${PPPOECLIENT_SO}" "${PPPOX_SO}" "${PPPOECLIENT_API_JSON}" "${PPPOX_API_JSON}"; do
  if [[ -z "${path}" || ! -f "${path}" ]]; then
    echo "Failed to locate expected build artifact: ${path}" >&2
    exit 1
  fi
done

mkdir -p "${LIBROOT}" "${APIDIR}" "${DOCROOT}"

install -m 755 "${PPPOECLIENT_SO}" "${LIBROOT}/pppoeclient_plugin.so"
install -m 755 "${PPPOX_SO}" "${LIBROOT}/pppox_plugin.so"
install -m 644 "${PPPOECLIENT_API_JSON}" "${APIDIR}/pppoeclient.api.json"
install -m 644 "${PPPOX_API_JSON}" "${APIDIR}/pppox.api.json"
install -m 644 "${REPO_ROOT}/LICENSE" "${DOCROOT}/LICENSE"

cat > "${DOCROOT}/README.md" <<EOF
# VPP PPPoE Client Prebuilt Plugin Package

This package contains prebuilt VPP plugin binaries for:

- pppoeclient_plugin.so
- pppox_plugin.so

It also includes:

- pppoeclient.api.json
- pppox.api.json

Package target VPP ref:
- ${VPP_REF}

Source commit:
- ${FULL_SHA}

Installed locations:
- Plugin binaries: ${PLUGIN_LIB_DIR}
- API JSON files: /usr/share/vpp/api/plugins

Usage:
1. Install a matching VPP runtime version for ${VPP_REF}
2. Install this package
3. Enable the plugins in VPP if needed

Notes:
- These are prebuilt plugin packages, not full VPP packages
- Source-based integration remains documented in the repository README
EOF

FPM_ARGS=(
  -s dir
  -t "${PACKAGE_TYPE}"
  -n "${PACKAGE_NAME}"
  -v "${VPP_VERSION}"
  --iteration "${PACKAGE_ITERATION}"
  -a "${PACKAGE_ARCH}"
  --description "Prebuilt VPP PPPoE client plugins for ${VPP_REF}"
  --url "https://github.com/Hi-Jiajun/vpp-pppoeclient"
  --license "Apache-2.0"
  --maintainer "Hi-Jiajun"
  --package "${OUTPUT_DIR}/${ASSET_NAME}"
  -C "${PKGROOT}"
  -d "vpp"
  .
)

echo "Packaging ${ASSET_NAME}"
fpm "${FPM_ARGS[@]}"

echo "Built asset:"
echo "  ${OUTPUT_DIR}/${ASSET_NAME}"
