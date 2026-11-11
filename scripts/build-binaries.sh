#!/usr/bin/env bash

# Builds every Revaulter binary for a single release target, then packages them into an archive.
#
# Usage:
#   BUILD_ID=<id> [BUILD_VERSION=<version>] [BUILD_LDFLAGS=<flags>] [CYCLONEDX_GOMOD=<path>] scripts/build-binaries.sh <target>
#
# Targets:
#   linux-amd64  linux-arm64  linux-386  linux-armv7
#   macos-x64    macos-arm64
#   windows-x64  windows-arm64
#   freebsd-amd64  freebsd-arm64
#
# Binaries are staged in .bin/revaulter-<BUILD_ID>-<target>, and the archive is written to .out
# Windows targets produce a .zip, every other target a .tar.gz
# When CYCLONEDX_GOMOD is the path to cyclonedx-gomod, a CycloneDX SBOM for each binary is also written to .out, as revaulter-<BUILD_ID>-<target>-<binary>.cdx.json

set -euo pipefail

# Resolved before anything changes the working directory
script_path="${BASH_SOURCE[0]}"

# Release binaries are statically linked
export CGO_ENABLED=0

# Every binary that ships in a release archive, as "<name>:<package>"
BINARIES=(
  "revaulter:./cmd/revaulter"
  "revaulter-cli:./cmd/cli"
  "revaulter-edit:./cmd/edit"
)

usage() {
  sed -n '3,16p' "${script_path}" | sed 's|^# \?||'
}

if [[ $# -ne 1 ]]; then
  echo "Error: expected a single target" >&2
  usage >&2
  exit 1
fi

target="$1"

if [[ -z "${BUILD_ID:-}" ]]; then
  echo "Error: the BUILD_ID environment variable is required" >&2
  usage >&2
  exit 1
fi

# Extension of the executables, and format of the archive: only Windows differs
ext=""
archive="tar.gz"
goarm=""

case "${target}" in
  linux-amd64) goos="linux"; goarch="amd64" ;;
  linux-arm64) goos="linux"; goarch="arm64" ;;
  linux-386) goos="linux"; goarch="386" ;;
  linux-armv7) goos="linux"; goarch="arm"; goarm="7" ;;
  macos-x64) goos="darwin"; goarch="amd64" ;;
  macos-arm64) goos="darwin"; goarch="arm64" ;;
  windows-x64) goos="windows"; goarch="amd64"; ext=".exe"; archive="zip" ;;
  windows-arm64) goos="windows"; goarch="arm64"; ext=".exe"; archive="zip" ;;
  freebsd-amd64) goos="freebsd"; goarch="amd64" ;;
  freebsd-arm64) goos="freebsd"; goarch="arm64" ;;
  *)
    echo "Error: unknown target '${target}'" >&2
    usage >&2
    exit 1
    ;;
esac

# Run from the root of the repository, so the paths below do not depend on where the script was invoked from
cd "$(dirname "${script_path}")/.."

name="revaulter-${BUILD_ID}-${target}"
stage=".bin/${name}"

echo -e "\n###\nBuilding ${goos}/${goarch}${goarm:+v${goarm}} into ${stage}\n"

mkdir -p .out "${stage}"

for entry in "${BINARIES[@]}"; do
  binary="${entry%%:*}"
  pkg="${entry#*:}"

  echo "Building ${binary}${ext} from ${pkg}"
  GOOS="${goos}" GOARCH="${goarch}" GOARM="${goarm}" \
    go build \
      -ldflags "${BUILD_LDFLAGS:-}" \
      -o "${stage}/${binary}${ext}" \
      -trimpath \
      "${pkg}"
done

# One SBOM per binary, generated from the module list that Go embeds in it, so it matches exactly what was compiled for this target
# cyclonedx-gomod reads the build settings from the binary, but takes the GOOS and GOARCH in package URLs from `go env`, so they must be set to match the build
if [[ -n "${CYCLONEDX_GOMOD:-}" ]]; then
  for entry in "${BINARIES[@]}"; do
    binary="${entry%%:*}"

    echo "Generating SBOM for ${binary}${ext}"
    GOOS="${goos}" GOARCH="${goarch}" GOARM="${goarm}" \
      "${CYCLONEDX_GOMOD}" bin \
        -json \
        -std \
        -version "${BUILD_VERSION:-${BUILD_ID}}" \
        -output ".out/${name}-${binary}.cdx.json" \
        "${stage}/${binary}${ext}"
  done
fi

cp LICENSE.md "${stage}"
cp -r README.md "${stage}"

if [[ "${archive}" == "zip" ]]; then
  (cd "${stage}" && zip -r "../../.out/${name}.zip" .)
else
  (cd .bin && tar -czvf "../.out/${name}.tar.gz" "${name}")
fi
