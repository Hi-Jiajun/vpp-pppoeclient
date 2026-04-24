#!/usr/bin/env bash
set -euo pipefail

VPP_REPO_URL="https://github.com/FDio/vpp.git"
VPP_REF=""
PACKAGE_TYPE=""
PACKAGE_ARCH=""
DISTRO_ID=""
PLUGIN_LIB_DIR=""
MAKE_OS_ID=""
MAKE_OS_VERSION_ID=""
CC_OVERRIDE=""
SKIP_INSTALL_DEP=0
OUTPUT_DIR="dist"
SHORT_SHA=""
FULL_SHA=""
PLUGIN_SOURCE_DIR=""
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
  --make-os-id <id>        Optional OS_ID override passed into the VPP Makefile
  --make-os-version-id <v> Optional OS_VERSION_ID override passed into the VPP Makefile
  --cc <compiler>          Optional compiler override passed into the VPP Makefile
  --skip-install-dep       Skip VPP's top-level make install-dep step
  --output-dir <dir>       Output directory for built assets
  --short-sha <sha>        Short commit SHA for naming
  --full-sha <sha>         Full commit SHA recorded in docs
  --plugin-source-dir <d>  Path to the pppoeclient source tree (default: <repo>/src/plugins/pppoeclient)
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
    --make-os-id)
      MAKE_OS_ID="$2"
      shift 2
      ;;
    --make-os-version-id)
      MAKE_OS_VERSION_ID="$2"
      shift 2
      ;;
    --cc)
      CC_OVERRIDE="$2"
      shift 2
      ;;
    --skip-install-dep)
      SKIP_INSTALL_DEP=1
      shift
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
    --plugin-source-dir)
      PLUGIN_SOURCE_DIR="$2"
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

if [[ -z "${VPP_REF}" ]]; then
  echo "Missing required argument: --vpp-ref" >&2
  usage >&2
  exit 1
fi

MAKE_ARGS=()
if [[ -n "${MAKE_OS_ID}" ]]; then
  MAKE_ARGS+=("OS_ID=${MAKE_OS_ID}")
fi
if [[ -n "${MAKE_OS_VERSION_ID}" ]]; then
  MAKE_ARGS+=("OS_VERSION_ID=${MAKE_OS_VERSION_ID}")
fi
if [[ -n "${CC_OVERRIDE}" ]]; then
  MAKE_ARGS+=("CC=${CC_OVERRIDE}")
fi
MAKE_ARGS+=('VPP_EXTRA_CMAKE_ARGS=-DVPP_PLUGINS="ppp,dhcp,pppoeclient"')

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -z "${PLUGIN_SOURCE_DIR}" ]]; then
  PLUGIN_SOURCE_DIR="${REPO_ROOT}/src/plugins/pppoeclient"
fi
if [[ ! -d "${PLUGIN_SOURCE_DIR}" ]]; then
  echo "Plugin source directory not found: ${PLUGIN_SOURCE_DIR}" >&2
  exit 1
fi

if [[ -z "${FULL_SHA}" ]]; then
  FULL_SHA="$(git -C "${PLUGIN_SOURCE_DIR}" rev-parse HEAD 2>/dev/null || git -C "${REPO_ROOT}" rev-parse HEAD)"
fi

if [[ -z "${SHORT_SHA}" ]]; then
  SHORT_SHA="$(git -C "${PLUGIN_SOURCE_DIR}" rev-parse --short HEAD 2>/dev/null || git -C "${REPO_ROOT}" rev-parse --short HEAD)"
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

cat > "${TOOLBIN}/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

toolbin="__TOOLBIN__"
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

cmd=("${args[@]:$idx}")

if [[ ${#cmd[@]} -eq 0 ]]; then
  exit 0
fi

if [[ -x "${toolbin}/${cmd[0]}" ]]; then
  exec "${toolbin}/${cmd[0]}" "${cmd[@]:1}"
fi

resolved_cmd="$(command -v "${cmd[0]}" || true)"
if [[ -n "${resolved_cmd}" ]]; then
  exec "${resolved_cmd}" "${cmd[@]:1}"
fi

exec "${cmd[@]}"
EOF
sed -i "s|__TOOLBIN__|${TOOLBIN}|g" "${TOOLBIN}/sudo"
chmod +x "${TOOLBIN}/sudo"
export PATH="${TOOLBIN}:${PATH}"

REAL_DNF="$(command -v dnf || true)"
if [[ -n "${REAL_DNF}" ]]; then
  cat > "${TOOLBIN}/dnf" <<EOF
#!/usr/bin/env bash
set -euo pipefail

rewrite_group_args() {
  local rewritten=()
  local arg
  for arg in "\$@"; do
    if [[ "\${arg}" == "C Development Tools and Libraries" ]]; then
      rewritten+=("@c-development")
    elif [[ "\${arg}" == "Development Tools" ]]; then
      rewritten+=("@development-tools")
    else
      if [[ "\${arg}" == @* ]]; then
        rewritten+=("\${arg}")
      else
        rewritten+=("\${arg}")
      fi
    fi
  done
  printf '%s\n' "\${rewritten[@]}"
}

if [[ "\${1:-}" == "groupinstall" ]]; then
  shift
  mapfile -t _group_args < <(rewrite_group_args "\$@")
  exec "${REAL_DNF}" install "\${_group_args[@]}"
fi

if [[ "\${1:-}" == "group" && "\${2:-}" == "install" ]]; then
  shift 2
  mapfile -t _group_args < <(rewrite_group_args "\$@")
  exec "${REAL_DNF}" install "\${_group_args[@]}"
fi

exec "${REAL_DNF}" "\$@"
EOF
  chmod +x "${TOOLBIN}/dnf"
  export PATH="${TOOLBIN}:${PATH}"
fi

if ! command -v debuginfo-install >/dev/null 2>&1; then
  cat > "${TOOLBIN}/debuginfo-install" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF
  chmod +x "${TOOLBIN}/debuginfo-install"
  export PATH="${TOOLBIN}:${PATH}"
fi

echo "Cloning ${VPP_REPO_URL} at ${VPP_REF}"
git clone --branch "${VPP_REF}" "${VPP_REPO_URL}" "${VPP_WORKTREE}"

# For non-tag refs (e.g. branch names), detect version from git history
if ! [[ "${VPP_REF}" =~ ^v[0-9] ]]; then
  git -C "${VPP_WORKTREE}" fetch --tags https://github.com/FDio/vpp.git || true
  VPP_REF="$(git -C "${VPP_WORKTREE}" describe --tags --abbrev=0 HEAD 2>/dev/null || echo "v0.0")"
  echo "Detected VPP version from git: ${VPP_REF}"
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

echo "Overlaying current plugin sources"
rsync -a --delete "${PLUGIN_SOURCE_DIR}/" "${VPP_WORKTREE}/src/plugins/pppoeclient/"

if [[ "${SKIP_INSTALL_DEP}" -eq 0 ]]; then
  echo "Installing VPP build dependencies"
  export DEBIAN_FRONTEND=noninteractive
  make -C "${VPP_WORKTREE}" UNATTENDED=y SUDO= "${MAKE_ARGS[@]}" install-dep
else
  echo "Skipping VPP top-level install-dep step"
  mkdir -p "${VPP_WORKTREE}/build-root"
  touch "${VPP_WORKTREE}/build-root/.deps.ok"
fi

echo "Building plugin binaries against ${VPP_REF}"
make -C "${VPP_WORKTREE}" "${MAKE_ARGS[@]}" build-release

PPPOECLIENT_SO="$(find "${VPP_WORKTREE}/build-root" -type f -name 'pppoeclient_plugin.so' | head -n 1)"
PPPOECLIENT_API_JSON="$(find "${VPP_WORKTREE}/build-root" -type f -path '*/share/vpp/api/plugins/pppoeclient.api.json' | head -n 1)"
PPPOX_API_JSON="$(find "${VPP_WORKTREE}/build-root" -type f -path '*/share/vpp/api/plugins/pppox.api.json' | head -n 1)"

for path in "${PPPOECLIENT_SO}" "${PPPOECLIENT_API_JSON}" "${PPPOX_API_JSON}"; do
  if [[ -z "${path}" || ! -f "${path}" ]]; then
    echo "Failed to locate expected build artifact: ${path}" >&2
    exit 1
  fi
done

mkdir -p "${LIBROOT}" "${APIDIR}" "${DOCROOT}"

install -m 755 "${PPPOECLIENT_SO}" "${LIBROOT}/pppoeclient_plugin.so"
install -m 644 "${PPPOECLIENT_API_JSON}" "${APIDIR}/pppoeclient.api.json"
install -m 644 "${PPPOX_API_JSON}" "${APIDIR}/pppox.api.json"
install -m 644 "${REPO_ROOT}/LICENSE" "${DOCROOT}/LICENSE"
install -m 644 "${REPO_ROOT}/THIRD_PARTY_LICENSES.md" "${DOCROOT}/THIRD_PARTY_LICENSES.md"

cat > "${DOCROOT}/README.md" <<EOF
# VPP PPPoE Client Prebuilt Plugin Package

This package contains the prebuilt VPP plugin binary:

- pppoeclient_plugin.so  (bundles the PPPoE client and the PPPoX core)

It also includes the API JSON descriptors:

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
- See THIRD_PARTY_LICENSES.md for mixed third-party licensing in the pppd-derived sources
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
