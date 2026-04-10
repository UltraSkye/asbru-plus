#!/bin/sh
# ci/no-shell-form.sh
# Heuristic regression check: warn about NEW shell-form system / qx /
# backtick interpolation in Perl source. Many existing sites are
# guarded by upstream input validation regex; we don't fail the build
# on the legacy set, but we ANNOUNCE so a reviewer can compare against
# git history when a PR adds new ones.
#
# Exit 0 always — reviewer responsibility to gate.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> shell-form audit (informational, does not fail build)"

# Strict pattern: bare system "..." with interpolation. We exclude
# patterns that are clearly inside character classes (regex), POD
# code blocks (4-space indent), or already-quoted with shell-quote.
PATTERN='(^|[^q])system\s+"[^"]*\$[a-zA-Z_]'

FOUND=0
for f in $(git ls-files 'lib/**/*.pm' 'lib/*.pm' 'asbru-cm' 2>/dev/null); do
    matches=$(grep -nE "$PATTERN" "$f" 2>/dev/null | grep -v '^\s*#' || true)
    if [ -n "$matches" ]; then
        echo
        echo "::warning file=$f::shell-form system with interpolation"
        echo "$matches" | sed 's/^/    /'
        FOUND=$(( FOUND + $(echo "$matches" | wc -l) ))
    fi
done

if [ "$FOUND" = 0 ]; then
    echo "    (clean)"
else
    echo
    echo "==> $FOUND occurrences. Reviewer: confirm none are NEW vs main."
fi

exit 0
