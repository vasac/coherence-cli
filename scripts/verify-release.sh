#!/bin/bash
#
# Copyright (c) 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.
#
# Verify unauthenticated public downloads before publishing stable.txt.
# Usage: verify-release.sh VERSION EXPECTED_MANIFEST
set -euo pipefail

if [ "$#" -ne 2 ] || [[ ! "$1" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]]; then
    echo "Usage: $0 VERSION EXPECTED_MANIFEST" >&2
    exit 1
fi
version=$1
manifest="cohctl-${version}-checksums.txt"
url="https://github.com/oracle/coherence-cli/releases/download/${version}"
temp=$(mktemp -d)
trap 'rm -rf -- "${temp}"' EXIT
cp -- "$2" "${temp}/expected.txt"
assets=("cohctl-${version}-linux-amd64" "cohctl-${version}-linux-arm64"
    "cohctl-${version}-linux-386" "cohctl-${version}-windows-amd64.exe"
    "cohctl-${version}-windows-arm64.exe" docs.zip)

download() {
    # Newly uploaded assets can take time to become publicly downloadable.
    # Bound both retries and request duration, including HTTP availability errors.
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 --retry-max-time 120 \
        --connect-timeout 10 --max-time 30 -o "${temp}/$1" "${url}/$1"
}

download "${manifest}"
cmp "${temp}/expected.txt" "${temp}/${manifest}"

# Validate the entire manifest before allowing sha256sum to read any filenames.
awk -v version="${version}" '
    BEGIN {
        names["cohctl-" version "-linux-amd64"] = 1
        names["cohctl-" version "-linux-arm64"] = 1
        names["cohctl-" version "-linux-386"] = 1
        names["cohctl-" version "-windows-amd64.exe"] = 1
        names["cohctl-" version "-windows-arm64.exe"] = 1
        names["docs.zip"] = 1
    }
    {
        if (NF != 2 || !($2 in names) || seen[$2]++ || length($1) != 64 ||
            $1 ~ /[^0-9a-f]/ || $0 != $1 "  " $2) bad = 1
    }
    END { if (bad || NR != 6) exit 1 }
' "${temp}/${manifest}"

for asset in "${assets[@]}"; do
    download "${asset}"
done
(cd "${temp}" && sha256sum -c "${manifest}")
