package PACWayland;

###############################################################################
# Wayland detection and X11 compatibility helpers for Ásbrú Plus
#
# Ásbrú Plus runs its GTK UI under X11 (via Xwayland when on Wayland) to keep
# GtkSocket-based RDP/VNC embedding working.  This module detects the active
# display server and provides helpers to build correct subprocess environment
# strings and RDP/VNC command adjustments.
###############################################################################

use strict;
use warnings;
use Exporter;

our @ISA       = qw(Exporter);
our @EXPORT_OK = qw(
    is_wayland
    wayland_env_for_x11
    rdp_client_for_wayland
    wayland_rdesktop_opts
    status_line
);

# ---------------------------------------------------------------------------
# is_wayland()
# Returns 1 when the current session is a Wayland session (either native
# or XWayland).  Detection order:
#   1. $WAYLAND_DISPLAY is set            → definitely Wayland
#   2. XDG_SESSION_TYPE eq 'wayland'      → systemd/logind says so
# Returns 0 otherwise (plain X11).
# ---------------------------------------------------------------------------
sub is_wayland {
    return 1 if $ENV{WAYLAND_DISPLAY};
    return 1 if ( $ENV{XDG_SESSION_TYPE} // '' ) eq 'wayland';
    return 0;
}

# ---------------------------------------------------------------------------
# wayland_env_for_x11()
# Returns a shell-safe environment prefix that forces GTK subprocesses to
# use the X11 backend so that GtkSocket/XID embedding keeps working.
# Returns empty string when already on X11 (no-op).
# ---------------------------------------------------------------------------
sub wayland_env_for_x11 {
    return is_wayland() ? 'GDK_BACKEND=x11 ' : '';
}

# ---------------------------------------------------------------------------
# rdp_client_for_wayland($preferred_client)
# On Wayland, rdesktop's X embedding path is unreliable — auto-upgrade to
# xfreerdp when it is available.  Falls back to the preferred client if
# xfreerdp is not found.
# ---------------------------------------------------------------------------
sub rdp_client_for_wayland {
    my ($preferred) = @_;
    return $preferred unless is_wayland();
    return $preferred unless $preferred eq 'rdesktop';

    # Try to find xfreerdp or xfreerdp3
    for my $bin (qw(xfreerdp3 xfreerdp)) {
        if (system("which $bin >/dev/null 2>&1") == 0) {
            return $bin;
        }
    }
    return $preferred;   # xfreerdp not found — keep rdesktop
}

# ---------------------------------------------------------------------------
# wayland_rdesktop_opts()
# Returns extra rdesktop flags that improve performance/compatibility when
# running rdesktop through Xwayland.
# ---------------------------------------------------------------------------
sub wayland_rdesktop_opts {
    return is_wayland() ? '-P -z -x l' : '';
}

# ---------------------------------------------------------------------------
# status_line()
# Returns a human-readable one-liner for startup logging.
# ---------------------------------------------------------------------------
sub status_line {
    if ( is_wayland() ) {
        return sprintf(
            'Wayland session detected (WAYLAND_DISPLAY=%s, XDG_SESSION_TYPE=%s) — using Xwayland for GTK',
            $ENV{WAYLAND_DISPLAY}    // '(unset)',
            $ENV{XDG_SESSION_TYPE}   // '(unset)',
        );
    }
    return 'X11 session';
}

1;
