#!/usr/bin/env bash
# install.sh — one-shot installer for Ásbrú Plus.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/UltraSkye/asbru-plus/master/install.sh | bash
#   curl -sSL https://raw.githubusercontent.com/UltraSkye/asbru-plus/master/install.sh | bash -s -- --channel=snapshot
#   curl -sSL https://raw.githubusercontent.com/UltraSkye/asbru-plus/master/install.sh | bash -s -- --appimage
#
# Detects the host distro/family and downloads the matching .deb / .rpm /
# .AppImage from the latest release on GitHub. Refuses to run as root unless
# package install needs sudo (it'll prompt then).

set -euo pipefail

REPO="UltraSkye/asbru-plus"
CHANNEL="release"      # release | snapshot
WANT_APPIMAGE=0
INSTALL_PREFIX="${HOME}/.local/bin"

err() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
log() { printf '\033[36m›\033[0m %s\n' "$*"; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --channel=*)    CHANNEL="${1#*=}" ;;
        --appimage)     WANT_APPIMAGE=1 ;;
        --prefix=*)     INSTALL_PREFIX="${1#*=}" ;;
        --help|-h)
            sed -n '2,12p' "$0" | sed 's/^# //; s/^#//'
            exit 0 ;;
        *)              err "unknown argument: $1" ;;
    esac
    shift
done

# Pick the release tag.
case "$CHANNEL" in
    release)
        TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
                | grep -oE '"tag_name"\s*:\s*"[^"]+"' | head -n1 | cut -d'"' -f4 || true)"
        [ -n "${TAG:-}" ] || err "no released version found in ${REPO}; try --channel=snapshot"
        ;;
    snapshot)
        TAG="snapshot"
        ;;
    *)
        err "unknown channel: $CHANNEL (use release or snapshot)" ;;
esac

log "channel=$CHANNEL tag=$TAG"

ASSETS_JSON="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/tags/${TAG}")" \
    || err "cannot fetch release info for ${TAG}"

# Helper: pick a download URL whose filename matches a regex.
pick_url() {
    local pattern="$1"
    printf '%s' "$ASSETS_JSON" \
        | grep -oE '"browser_download_url"\s*:\s*"[^"]+"' \
        | cut -d'"' -f4 \
        | grep -E "$pattern" | head -n1
}

# Detect distro family.
. /etc/os-release 2>/dev/null || err "/etc/os-release not found — unsupported distro"

if [ "$WANT_APPIMAGE" -eq 1 ]; then
    URL="$(pick_url 'AppImage$')"
    [ -n "${URL:-}" ] || err "no AppImage in release ${TAG}"
    DEST="${INSTALL_PREFIX}/asbru-plus.AppImage"
    mkdir -p "${INSTALL_PREFIX}"
    log "downloading $URL"
    curl -fSL -o "$DEST" "$URL"
    chmod +x "$DEST"
    log "installed AppImage at $DEST"
    log "run:  $DEST"
    exit 0
fi

case "${ID_LIKE:-$ID}" in
    *debian*|*ubuntu*)
        FAMILY=deb ;;
    *rhel*|*fedora*|*centos*)
        FAMILY=rpm ;;
    *)
        case "$ID" in
            debian|ubuntu|linuxmint|pop|elementary|raspbian|kali)        FAMILY=deb ;;
            fedora|rhel|centos|almalinux|rocky|ol|amzn)                  FAMILY=rpm ;;
            *)
                log "unrecognized distro '$ID' — falling back to AppImage"
                exec "$0" --appimage --channel="$CHANNEL" ;;
        esac ;;
esac

case "$FAMILY" in
    deb)
        # Prefer the asset whose filename contains our codename, then any .deb.
        CODENAME="${VERSION_CODENAME:-}"
        URL=""
        [ -n "$CODENAME" ] && URL="$(pick_url "${CODENAME}.*\.deb$")"
        [ -z "$URL" ]      && URL="$(pick_url '\.deb$')"
        [ -n "${URL:-}" ]  || err "no .deb asset found in release ${TAG}"
        FNAME="$(basename "$URL")"
        log "downloading $FNAME"
        curl -fSL -o "/tmp/${FNAME}" "$URL"
        log "installing — sudo password may be required"
        sudo apt-get update
        sudo apt-get install -y "/tmp/${FNAME}"
        rm -f "/tmp/${FNAME}"
        ;;
    rpm)
        VID="${VERSION_ID%%.*}"
        URL=""
        # Try to match el<n>, fc<n>, alma<n> in filename.
        [ -n "$VID" ] && URL="$(pick_url "(el|fc|alma)${VID}.*\.rpm$")"
        [ -z "$URL" ] && URL="$(pick_url '\.rpm$')"
        [ -n "${URL:-}" ] || err "no .rpm asset found in release ${TAG}"
        FNAME="$(basename "$URL")"
        log "downloading $FNAME"
        curl -fSL -o "/tmp/${FNAME}" "$URL"
        log "installing — sudo password may be required"
        if command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y "/tmp/${FNAME}"
        else
            sudo yum install -y "/tmp/${FNAME}"
        fi
        rm -f "/tmp/${FNAME}"
        ;;
esac

log "done. Run:  asbru-cm"
