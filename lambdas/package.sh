#!/usr/bin/env bash
# set -x
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

for d in */ ; do
  TMP_DIR=$(mktemp -d)
  echo "Installing to: ${TMP_DIR}"
  (
    pushd "${d}"
    VERSION=$(cat setup.py | grep "version" | cut -d "'" -f 2)
    python3 -m pip install . --target "${TMP_DIR}"
    python3 -m pip install -r requirements.txt --target "${TMP_DIR}"
    popd
    pushd "${TMP_DIR}"
    BUNDLE="${SCRIPT_DIR}/${d%"/"}-${VERSION}.zip"
    zip -r -X "${BUNDLE}" .
    echo "Wrote bundle: ${BUNDLE}"
    rm -rf "${TMP_DIR}"
    popd
  )
done
