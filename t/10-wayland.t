#!/usr/bin/perl
# t/10-wayland.t — Tests for PACWayland detection and compatibility helpers
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

use lib "$RealBin/../lib";
use lib "$RealBin/../lib/ex";

eval { require PACWayland } or BAIL_OUT("Cannot load PACWayland: $@");

# ── is_wayland() detection ────────────────────────────────────────────────────

subtest 'is_wayland — WAYLAND_DISPLAY set' => sub {
    local $ENV{WAYLAND_DISPLAY}   = 'wayland-0';
    local $ENV{XDG_SESSION_TYPE}  = 'x11';      # contradicted by WAYLAND_DISPLAY
    ok(PACWayland::is_wayland(), 'WAYLAND_DISPLAY triggers is_wayland');
};

subtest 'is_wayland — XDG_SESSION_TYPE=wayland' => sub {
    local $ENV{WAYLAND_DISPLAY}   = undef;
    delete $ENV{WAYLAND_DISPLAY};
    local $ENV{XDG_SESSION_TYPE}  = 'wayland';
    ok(PACWayland::is_wayland(), 'XDG_SESSION_TYPE=wayland triggers is_wayland');
};

subtest 'is_wayland — plain X11 session' => sub {
    local $ENV{WAYLAND_DISPLAY}   = undef;
    delete $ENV{WAYLAND_DISPLAY};
    local $ENV{XDG_SESSION_TYPE}  = 'x11';
    ok(!PACWayland::is_wayland(), 'X11 session: is_wayland returns false');
};

subtest 'is_wayland — no display vars at all' => sub {
    local $ENV{WAYLAND_DISPLAY}   = undef;
    delete $ENV{WAYLAND_DISPLAY};
    local $ENV{XDG_SESSION_TYPE}  = undef;
    delete $ENV{XDG_SESSION_TYPE};
    ok(!PACWayland::is_wayland(), 'No env vars: is_wayland returns false');
};

# ── wayland_env_for_x11() ─────────────────────────────────────────────────────

subtest 'wayland_env_for_x11 — returns prefix on Wayland' => sub {
    local $ENV{WAYLAND_DISPLAY} = 'wayland-0';
    my $prefix = PACWayland::wayland_env_for_x11();
    like($prefix, qr/GDK_BACKEND=x11/, 'prefix contains GDK_BACKEND=x11');
    like($prefix, qr/\s$/, 'prefix ends with a space');
};

subtest 'wayland_env_for_x11 — empty on X11' => sub {
    local $ENV{WAYLAND_DISPLAY}  = undef;
    delete $ENV{WAYLAND_DISPLAY};
    local $ENV{XDG_SESSION_TYPE} = 'x11';
    is(PACWayland::wayland_env_for_x11(), '', 'empty string on X11 session');
};

# ── rdp_client_for_wayland() ─────────────────────────────────────────────────

subtest 'rdp_client_for_wayland — xfreerdp unchanged on X11' => sub {
    local $ENV{WAYLAND_DISPLAY}  = undef;
    delete $ENV{WAYLAND_DISPLAY};
    local $ENV{XDG_SESSION_TYPE} = 'x11';
    is(PACWayland::rdp_client_for_wayland('xfreerdp'), 'xfreerdp',
        'xfreerdp unchanged on X11');
    is(PACWayland::rdp_client_for_wayland('rdesktop'), 'rdesktop',
        'rdesktop unchanged on X11');
};

subtest 'rdp_client_for_wayland — xfreerdp unchanged on Wayland' => sub {
    local $ENV{WAYLAND_DISPLAY} = 'wayland-0';
    is(PACWayland::rdp_client_for_wayland('xfreerdp'), 'xfreerdp',
        'xfreerdp not upgraded (already modern)');
};

subtest 'rdp_client_for_wayland — rdesktop upgrade logic on Wayland' => sub {
    local $ENV{WAYLAND_DISPLAY} = 'wayland-0';
    my $result = PACWayland::rdp_client_for_wayland('rdesktop');
    # Either upgraded to xfreerdp/xfreerdp3 (if installed) or kept as rdesktop
    ok($result eq 'rdesktop' || $result =~ /xfreerdp/,
        "rdesktop on Wayland returns rdesktop or xfreerdp (got: $result)");
};

# ── wayland_rdesktop_opts() ───────────────────────────────────────────────────

subtest 'wayland_rdesktop_opts — performance flags on Wayland' => sub {
    local $ENV{WAYLAND_DISPLAY} = 'wayland-0';
    my $opts = PACWayland::wayland_rdesktop_opts();
    like($opts, qr/-P/,    'rdesktop -P (caching) present on Wayland');
    like($opts, qr/-z/,    'rdesktop -z (compression) present on Wayland');
    like($opts, qr/-x l/,  'rdesktop -x l (LAN quality) present on Wayland');
    like($opts, qr/-a 24/, 'rdesktop -a 24 (24-bit colour) present on Wayland');
};

subtest 'wayland_rdesktop_opts — empty on X11' => sub {
    local $ENV{WAYLAND_DISPLAY}  = undef;
    delete $ENV{WAYLAND_DISPLAY};
    local $ENV{XDG_SESSION_TYPE} = 'x11';
    is(PACWayland::wayland_rdesktop_opts(), '', 'no extra flags on X11');
};

# ── status_line() ─────────────────────────────────────────────────────────────

subtest 'status_line — Wayland' => sub {
    local $ENV{WAYLAND_DISPLAY} = 'wayland-0';
    my $line = PACWayland::status_line();
    like($line, qr/Wayland/i, 'status_line mentions Wayland');
    like($line, qr/Xwayland/i, 'status_line mentions Xwayland fallback');
};

subtest 'status_line — X11' => sub {
    local $ENV{WAYLAND_DISPLAY}  = undef;
    delete $ENV{WAYLAND_DISPLAY};
    local $ENV{XDG_SESSION_TYPE} = 'x11';
    my $line = PACWayland::status_line();
    like($line, qr/X11/, 'status_line says X11');
};

# ── asbru_conn integration — ASBRU_DEBUG and Wayland code present ────────────

subtest 'asbru_conn: ASBRU_DEBUG env var support' => sub {
    my $conn_file = "$RealBin/../lib/asbru_conn";
    open my $fh, '<', $conn_file or BAIL_OUT("Cannot read asbru_conn: $!");
    my $src = do { local $/; <$fh> }; close $fh;
    like($src, qr/ASBRU_DEBUG/,          'ASBRU_DEBUG referenced in asbru_conn');
    like($src, qr/ENV.*ASBRU_DEBUG/,     'read from %ENV');
};

subtest 'asbru_conn: Wayland integration' => sub {
    my $conn_file = "$RealBin/../lib/asbru_conn";
    open my $fh, '<', $conn_file or BAIL_OUT("Cannot read asbru_conn: $!");
    my $src = do { local $/; <$fh> }; close $fh;
    like($src, qr/PACWayland/,                        'PACWayland module used');
    like($src, qr/rdp_client_for_wayland/,            'rdesktop auto-upgrade present');
    like($src, qr/wayland_rdesktop_opts/,             'rdesktop Wayland flags present');
    like($src, qr/wm.class.*asbru.rdp/,               'xfreerdp wm-class for XID uniqueness');
    like($src, qr/width.*200|height.*150/,            'XID geometry sanity guard present');
};

subtest 'PACMain.pm: Wayland startup detection' => sub {
    my $main_file = "$RealBin/../lib/PACMain.pm";
    open my $fh, '<', $main_file or BAIL_OUT("Cannot read PACMain.pm: $!");
    my $src = do { local $/; <$fh> }; close $fh;
    like($src, qr/use PACWayland/,             'PACMain imports PACWayland');
    like($src, qr/PACWayland::status_line/,    'PACMain logs Wayland status');
    like($src, qr/PACWayland::is_wayland/,     'PACMain checks Wayland at startup');
    like($src, qr/GDK_BACKEND.*x11/,           'GDK_BACKEND=x11 warning present');
};

subtest 'asbru-cm: Wayland auto-restart' => sub {
    my $launcher = "$RealBin/../asbru-cm";
    open my $fh, '<', $launcher or BAIL_OUT("Cannot read asbru-cm: $!");
    my $src = do { local $/; <$fh> }; close $fh;
    like($src, qr/ASBRU_NO_WAYLAND_RESTART/,  'restart guard env var present');
    like($src, qr/GDK_BACKEND.*=.*x11/,        'GDK_BACKEND=x11 set before restart');
    like($src, qr/exec.*\$\^X/,                'exec re-launches with correct interpreter');
};

subtest 'PACWayland: ASBRU_FORCE_XFREERDP support' => sub {
    local $ENV{WAYLAND_DISPLAY}      = undef; delete $ENV{WAYLAND_DISPLAY};
    local $ENV{XDG_SESSION_TYPE}     = 'x11';
    local $ENV{ASBRU_FORCE_XFREERDP} = '1';
    my $result = PACWayland::rdp_client_for_wayland('rdesktop');
    # Either upgraded to xfreerdp (if installed) or kept as rdesktop
    ok($result eq 'rdesktop' || $result =~ /xfreerdp/,
        "ASBRU_FORCE_XFREERDP on X11: got rdesktop or xfreerdp (got: $result)");
};

subtest 'PACWayland: wayland_rdesktop_opts includes -a 24' => sub {
    local $ENV{WAYLAND_DISPLAY} = 'wayland-0';
    my $opts = PACWayland::wayland_rdesktop_opts();
    like($opts, qr/-a 24/, 'rdesktop -a 24 (24-bit colour) present on Wayland');
};

done_testing();
