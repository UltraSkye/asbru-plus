#!/usr/bin/env bash
set -euo pipefail

cd /build/src

echo "============================================================"
echo " Step 1: Extract version from source"
echo "============================================================"
VERSION="$(perl -ne 'print $1 if /our\s+\$APPVERSION\s*=\s*'"'"'([^'"'"']+)'"'"'/' lib/PACUtils.pm)"
echo "Version: ${VERSION}"

echo ""
echo "============================================================"
echo " Step 2: Copy debian/ packaging files to source root"
echo "============================================================"
cp -r dist/deb/* .
echo "debian/ ready."

echo ""
echo "============================================================"
echo " Step 3: Build .deb package"
echo "============================================================"
DEB_BUILD_OPTIONS=nocheck dpkg-buildpackage -b -us -uc -rfakeroot

DEB_FILE="/build/asbru-plus_${VERSION}-1_all.deb"

if [ ! -f "${DEB_FILE}" ]; then
    echo "ERROR: Expected ${DEB_FILE} not found. Files in /build:"
    ls -la /build/
    exit 1
fi

echo "Built: ${DEB_FILE}"

echo ""
echo "============================================================"
echo " Step 4: Validate package metadata"
echo "============================================================"
export DEB_FILE
dpkg-deb --info "${DEB_FILE}"

echo ""
echo "============================================================"
echo " Step 5: Validate package contents"
echo "============================================================"
dpkg-deb --contents "${DEB_FILE}"

echo ""
echo "============================================================"
echo " Step 6: Run Perl tests on .deb structure"
echo "============================================================"
prove -lv t/10-deb-contents.t

echo ""
echo "============================================================"
echo " Step 7: Install package"
echo "============================================================"
dpkg -i "${DEB_FILE}"

echo ""
echo "============================================================"
echo " Step 8: Run post-install verification tests"
echo "============================================================"
prove -lv t/11-install-check.t

echo ""
echo "============================================================"
echo " Step 9: Run lintian (informational, non-fatal)"
echo "============================================================"
lintian --profile debian "${DEB_FILE}" \
    --suppress-tags \
    no-changelog-file,no-copyright-file,missing-depends-line || true

echo ""
echo "============================================================"
echo " All build tests PASSED"
echo "============================================================"

# Copy artifact to /output if volume is mounted
mkdir -p /output
cp "${DEB_FILE}" /output/
echo "Artifact saved to /output/$(basename "${DEB_FILE}")"
