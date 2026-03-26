#!/usr/bin/env bash
set -euo pipefail

PACKAGE_TYPE=""
PACKAGE_FILE=""
PLUGIN_LIB_DIR=""

usage() {
  cat <<'EOF'
Usage: scripts/verify-prebuilt-package.sh [options]

Options:
  --package-type <type>    deb or rpm
  --package-file <path>    Built package path
  --plugin-lib-dir <path>  Expected plugin install directory
  -h, --help               Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --package-type)
      PACKAGE_TYPE="$2"
      shift 2
      ;;
    --package-file)
      PACKAGE_FILE="$2"
      shift 2
      ;;
    --plugin-lib-dir)
      PLUGIN_LIB_DIR="$2"
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

if [[ -z "${PACKAGE_TYPE}" || -z "${PACKAGE_FILE}" || -z "${PLUGIN_LIB_DIR}" ]]; then
  echo "Missing required arguments" >&2
  usage >&2
  exit 1
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

expect_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "Expected file missing: ${path}" >&2
    exit 1
  fi
  if [[ ! -s "${path}" ]]; then
    echo "Expected file is empty: ${path}" >&2
    exit 1
  fi
}

verify_elf() {
  local path="$1"
  local magic
  magic="$(od -An -tx1 -N4 "${path}" | tr -d ' \n')"
  if [[ "${magic}" != "7f454c46" ]]; then
    echo "Expected ELF shared object, got unexpected header for: ${path}" >&2
    exit 1
  fi
}

PACKAGE_FILE="$(cd "$(dirname "${PACKAGE_FILE}")" && pwd)/$(basename "${PACKAGE_FILE}")"

if [[ ! -f "${PACKAGE_FILE}" ]]; then
  echo "Package file not found: ${PACKAGE_FILE}" >&2
  exit 1
fi

WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pkg-verify.XXXXXX")"
trap 'rm -rf "${WORK_ROOT}"' EXIT
ROOTDIR="${WORK_ROOT}/root"
mkdir -p "${ROOTDIR}"

case "${PACKAGE_TYPE}" in
  deb)
    require_cmd dpkg-deb

    package_depends="$(dpkg-deb -f "${PACKAGE_FILE}" Depends || true)"
    if [[ "${package_depends}" != *vpp* ]]; then
      echo "Expected package dependency on vpp, got: ${package_depends}" >&2
      exit 1
    fi

    dpkg-deb --info "${PACKAGE_FILE}" >/dev/null
    dpkg-deb --contents "${PACKAGE_FILE}" >/dev/null
    dpkg-deb --extract "${PACKAGE_FILE}" "${ROOTDIR}"
    ;;
  rpm)
    require_cmd rpm

    package_requires="$(rpm -qpR "${PACKAGE_FILE}")"
    if ! grep -Eq '^vpp([[:space:]]|$)' <<<"${package_requires}"; then
      echo "Expected package dependency on vpp, got:" >&2
      echo "${package_requires}" >&2
      exit 1
    fi

    rpm -qpi "${PACKAGE_FILE}" >/dev/null
    rpm -qpl "${PACKAGE_FILE}" >/dev/null
    rpm --root "${ROOTDIR}" --dbpath /var/lib/rpm --initdb >/dev/null
    rpm --root "${ROOTDIR}" --dbpath /var/lib/rpm --nodeps --nosignature -ivh "${PACKAGE_FILE}" >/dev/null
    ;;
  *)
    echo "Unsupported package type: ${PACKAGE_TYPE}" >&2
    exit 1
    ;;
esac

PPPOECLIENT_SO="${ROOTDIR}${PLUGIN_LIB_DIR}/pppoeclient_plugin.so"
PPPOX_SO="${ROOTDIR}${PLUGIN_LIB_DIR}/pppox_plugin.so"
PPPOECLIENT_API="${ROOTDIR}/usr/share/vpp/api/plugins/pppoeclient.api.json"
PPPOX_API="${ROOTDIR}/usr/share/vpp/api/plugins/pppox.api.json"

expect_file "${PPPOECLIENT_SO}"
expect_file "${PPPOX_SO}"
expect_file "${PPPOECLIENT_API}"
expect_file "${PPPOX_API}"

verify_elf "${PPPOECLIENT_SO}"
verify_elf "${PPPOX_SO}"

echo "Verified package smoke test: ${PACKAGE_FILE}"
