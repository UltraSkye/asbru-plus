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
echo " Step 2: Validate RPM spec file"
echo "============================================================"
rpmspec -q dist/rpm/asbru.spec \
    --define "_version ${VERSION}" \
    --define "_release 1" \
    --define "_github_version ${VERSION}" \
    || { echo "ERROR: rpmspec validation failed"; exit 1; }
echo "Spec file parses correctly."

echo ""
echo "============================================================"
echo " Step 3: Set up rpmbuild tree"
echo "============================================================"
rpmdev-setuptree
RPMBUILD_DIR="${HOME}/rpmbuild"

echo ""
echo "============================================================"
echo " Step 4: Create source tarball"
echo "============================================================"
TARBALL="${RPMBUILD_DIR}/SOURCES/asbru-plus-${VERSION}.tar.gz"
tar czf "${TARBALL}" \
    --transform "s,^\.,asbru-plus-${VERSION}," \
    --exclude='.git' \
    --exclude='./build' \
    --exclude='./docker' \
    --exclude='./t' \
    -C /build/src .
echo "Tarball created: ${TARBALL}"

echo ""
echo "============================================================"
echo " Step 5: Build RPM"
echo "============================================================"
cp dist/rpm/asbru.spec "${RPMBUILD_DIR}/SPECS/"

rpmbuild -ba "${RPMBUILD_DIR}/SPECS/asbru.spec" \
    --define "_version ${VERSION}" \
    --define "_release 1" \
    --define "_github_version ${VERSION}"

echo ""
echo "============================================================"
echo " Step 6: Validate built RPM"
echo "============================================================"
RPM_FILE="$(find "${RPMBUILD_DIR}/RPMS" -name 'asbru-plus-*.rpm' | head -1)"

if [ -z "${RPM_FILE}" ]; then
    echo "ERROR: No RPM file found in ${RPMBUILD_DIR}/RPMS"
    find "${RPMBUILD_DIR}" -name '*.rpm'
    exit 1
fi

echo "Built: ${RPM_FILE}"
rpm -qip "${RPM_FILE}"
echo ""
echo "Package contents:"
rpm -qlp "${RPM_FILE}"

echo ""
echo "============================================================"
echo " Step 7: Run Perl tests on RPM structure"
echo "============================================================"
export RPM_FILE
prove -lv t/12-rpm-contents.t

echo ""
echo "============================================================"
echo " All RPM build tests PASSED"
echo "============================================================"

# Save artifact
mkdir -p /output
cp "${RPM_FILE}" /output/
echo "Artifact saved to /output/$(basename "${RPM_FILE}")"
