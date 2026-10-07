#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Diridium Technologies Inc.
#
# Installs the five OIE engine jars this plugin builds against into the local
# Maven repository, taken from the published OIE distribution for the POM's
# mc.version. CI builds from the same tarball (.github/workflows/build.yml).
# Run it once per engine version.
#
# Usage:
#   ./scripts/install-engine-jars.sh
#
# The tarball is downloaded into target/oie-dist/ (gitignored, reused until the
# next mvn clean) and checked against the release's own sha256sums before
# anything is installed. Works on Linux and macOS; needs zip (see below).

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v zip >/dev/null 2>&1; then
    echo "error: zip is required to strip the engine jars' signatures (see the comment below)" >&2
    exit 1
fi

MC_VERSION="$(mvn -q -N help:evaluate -Dexpression=mc.version -DforceStdout)"
if [[ -z "${MC_VERSION}" ]]; then
    echo "error: could not read mc.version from pom.xml" >&2
    exit 1
fi
TARBALL="oie_unix_${MC_VERSION//./_}.tar.gz"
BASE_URL="https://github.com/OpenIntegrationEngine/engine/releases/download/v${MC_VERSION}"
DIST_DIR="target/oie-dist"

# sha256sum on Linux, shasum on macOS.
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

mkdir -p "${DIST_DIR}"
curl -fsSL -o "${DIST_DIR}/sha256sums" "${BASE_URL}/sha256sums"
# Lines read "<hash> *<file>" (binary mode) or "<hash>  <file>".
expected="$(awk -v f="${TARBALL}" '{ n = $2; sub(/^\*/, "", n) } n == f { print $1 }' "${DIST_DIR}/sha256sums")"
if [[ -z "${expected}" ]]; then
    echo "error: ${TARBALL} is not listed in ${BASE_URL}/sha256sums" >&2
    exit 1
fi

if [[ ! -f "${DIST_DIR}/${TARBALL}" || "$(sha256 "${DIST_DIR}/${TARBALL}")" != "${expected}" ]]; then
    echo "downloading ${TARBALL} from ${BASE_URL}"
    curl -fSL -o "${DIST_DIR}/${TARBALL}" "${BASE_URL}/${TARBALL}"
fi
actual="$(sha256 "${DIST_DIR}/${TARBALL}")"
if [[ "${actual}" != "${expected}" ]]; then
    echo "error: ${TARBALL} sha256 is ${actual}, the release lists ${expected}" >&2
    exit 1
fi

# artifactId:path inside the tarball (groupId com.mirth.connect for all five)
JARS=(
    "mirth-server:oie/server-lib/mirth-server.jar"
    "mirth-crypto:oie/server-lib/mirth-crypto.jar"
    "donkey-server:oie/server-lib/donkey/donkey-server.jar"
    "mirth-client-core:oie/server-lib/mirth-client-core.jar"
    "mirth-client:oie/client-lib/mirth-client.jar"
)

members=()
for entry in "${JARS[@]}"; do
    members+=("${entry#*:}")
done
tar -xzf "${DIST_DIR}/${TARBALL}" -C "${DIST_DIR}" "${members[@]}"

for entry in "${JARS[@]}"; do
    artifact="${entry%%:*}"
    jar_path="${DIST_DIR}/${entry#*:}"
    # The release's client-lib jars are signed by the OIE project and its
    # server-lib jars are not. The com.mirth.connect.plugins package spans
    # mirth-client and mirth-client-core, so loading a class from each in one
    # test JVM throws a signer-mismatch SecurityException. Strip the signatures
    # from the extracted copies (the tarball itself is never modified); they
    # mean nothing for a compile/test dependency. zip exits 12 when a jar has
    # no signature files to delete, which is fine.
    zip -q -d "${jar_path}" 'META-INF/*.SF' 'META-INF/*.RSA' 'META-INF/*.DSA' 'META-INF/*.EC' >/dev/null 2>&1 || [[ $? -eq 12 ]]
    echo "installing ${artifact}-${MC_VERSION}"
    mvn -q install:install-file \
        -Dfile="${jar_path}" \
        -DgroupId=com.mirth.connect \
        -DartifactId="${artifact}" \
        -Dversion="${MC_VERSION}" \
        -Dpackaging=jar
done

echo "done. ${#JARS[@]} jars installed at version ${MC_VERSION}."
