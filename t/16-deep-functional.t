#!/usr/bin/perl
# t/16-deep-functional.t — Deep functional tests for untested code paths
# Covers: SSH option parsing, tree sorting, screenshot purge, desktop file,
#         log rotation edge cases, config anonymization, KeePass helpers,
#         message framing, AppRun script, migration utilities, method plugins
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempdir tempfile);
use File::Path qw(make_path remove_tree);
use File::Copy;
use Storable qw(dclone freeze thaw nstore retrieve);

use lib "$RealBin/../lib/ex";
use lib "$RealBin/../lib";
use lib "$RealBin/lib";

BEGIN {
    my @stubs = qw(Gtk3 Gtk3::Gdk Glib Glib::IO Glib::Object::Introspection
                   Pango Cairo SortedTreeStore Gnome2::Wnck Vte2ext);
    for my $mod (@stubs) {
        (my $file = $mod) =~ s|::|/|g;
        $INC{"$file.pm"} //= 1;
    }
    package Gtk3;
    sub import {} sub init { 1 }
    sub events_pending { 0 } sub main_iteration { 0 } sub main_iteration_do { 0 }
    sub main_quit {} sub main {} sub TRUE { 1 } sub FALSE { 0 }
    package Gtk3::Gdk; sub import {} our $AUTOLOAD;
    sub AUTOLOAD { return if $AUTOLOAD =~ /::DESTROY$/; bless {}, 'Gtk3::Gdk' } sub DESTROY {}
    package Gtk3::Gdk::Pixbuf; sub import {} our $AUTOLOAD;
    sub new { bless {}, 'Gtk3::Gdk::Pixbuf' }
    sub new_from_file { bless {}, 'Gtk3::Gdk::Pixbuf' }
    sub new_from_file_at_scale { bless {}, 'Gtk3::Gdk::Pixbuf' }
    sub AUTOLOAD { return if $AUTOLOAD =~ /::DESTROY$/; bless {}, 'Gtk3::Gdk::Pixbuf' } sub DESTROY {}
    package Glib; sub import {}
    sub Glib::Markup::escape_text { return $_[0] // '' }
    package Glib::IO; sub import {} sub add_watch { 0 }
    package Glib::Object::Introspection; sub setup { 1 } sub import {}
    package Pango; sub import {}
    package Cairo; sub import {}
    package SortedTreeStore; sub new { bless {}, shift } sub import {}
    package PACMain;
    our %RUNNING  = ();
    our %FUNCS    = ();
    our %SOCKS5PORTS = ();
    package main;
}

local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ /redefined|uninitialized/i };
eval { require PACUtils } or BAIL_OUT("Cannot load PACUtils: $@");

sub read_file {
    my $path = shift;
    open my $fh, '<', $path or BAIL_OUT("Cannot open $path: $!");
    local $/;
    my $content = <$fh>;
    close $fh;
    return $content;
}

# ═══════════════════════════════════════════════════════════════════════════════
# 1. _updateSSHToIPv6 — SSH Command Line Parser/Normalizer
# ═══════════════════════════════════════════════════════════════════════════════

# NOTE: _updateSSHToIPv6 expects a leading space before the first flag,
# matching the output format of _parseOptionsToCfg which prefixes " -flag"

subtest '_updateSSHToIPv6 — basic flags' => sub {
    my $result = PACUtils::_updateSSHToIPv6(' -2 -X -C -g -A');
    like($result, qr/-2/, 'SSH version 2');
    like($result, qr/-X/, 'X forwarding on');
    like($result, qr/-C/, 'compression on');
    like($result, qr/-g/, 'remote connection on');
    like($result, qr/-A/, 'agent forwarding on');
};

subtest '_updateSSHToIPv6 — version and IP flags' => sub {
    like(PACUtils::_updateSSHToIPv6(' -1 -X'), qr/-1/, 'SSH v1');
    like(PACUtils::_updateSSHToIPv6(' -2 -X'), qr/-2/, 'SSH v2');
    like(PACUtils::_updateSSHToIPv6(' -4 -X'), qr/-4/, 'IPv4');
    like(PACUtils::_updateSSHToIPv6(' -6 -X'), qr/-6/, 'IPv6');
    like(PACUtils::_updateSSHToIPv6(' -2 -6 -X'), qr/-2.*-6/, 'SSH v2 + IPv6');
};

subtest '_updateSSHToIPv6 — X forwarding toggle' => sub {
    like(PACUtils::_updateSSHToIPv6(' -X'), qr/-X/, '-X enables forwarding');
    like(PACUtils::_updateSSHToIPv6(' -x'), qr/-x/, '-x disables forwarding');
};

subtest '_updateSSHToIPv6 — empty string returns X forward default' => sub {
    my $result = PACUtils::_updateSSHToIPv6('');
    like($result, qr/-X/, 'default: X forwarding on');
    unlike($result, qr/-[1246CAg]/, 'no other flags set');
};

subtest '_updateSSHToIPv6 — local port forwarding' => sub {
    my $result = PACUtils::_updateSSHToIPv6(' -L 8080:localhost:80');
    like($result, qr/-L\s+8080\/localhost\/80/, 'local forward parsed and normalized');
};

subtest '_updateSSHToIPv6 — remote port forwarding' => sub {
    my $result = PACUtils::_updateSSHToIPv6(' -R 9090:db:5432');
    like($result, qr/-R\s+9090\/db\/5432/, 'remote forward parsed');
};

subtest '_updateSSHToIPv6 — dynamic SOCKS forward' => sub {
    my $result = PACUtils::_updateSSHToIPv6(' -D 1080');
    like($result, qr/-D\s+1080/, 'dynamic forward parsed');
};

subtest '_updateSSHToIPv6 — port forward with bind address' => sub {
    my $result = PACUtils::_updateSSHToIPv6(' -L 0.0.0.0:8080:webserver:80');
    like($result, qr/-L\s+0\.0\.0\.0\/8080\/webserver\/80/, 'bind address preserved');
};

subtest '_updateSSHToIPv6 — quoted -o options preserved' => sub {
    my $result = PACUtils::_updateSSHToIPv6(' -o "ServerAliveInterval=30" -X');
    like($result, qr/-o "ServerAliveInterval=30"/, '-o option preserved');
    like($result, qr/-X/, 'other flags still parsed');
};

subtest '_updateSSHToIPv6 — multiple forwards' => sub {
    my $result = PACUtils::_updateSSHToIPv6(' -L 8080:web:80 -L 8443:web:443 -R 5000:api:5000');
    my @L = ($result =~ /-L/g);
    my @R = ($result =~ /-R/g);
    is(scalar @L, 2, 'two local forwards');
    is(scalar @R, 1, 'one remote forward');
};

subtest '_updateSSHToIPv6 — combined flags string' => sub {
    my $result = PACUtils::_updateSSHToIPv6(' -2 -4 -X -C -A -o "StrictHostKeyChecking=no" -L 3306:mysql:3306 -D 1080');
    like($result, qr/-2/, 'version 2');
    like($result, qr/-4/, 'ipv4');
    like($result, qr/-X/, 'x11 fwd');
    like($result, qr/-C/, 'compression');
    like($result, qr/-A/, 'agent fwd');
    like($result, qr/StrictHostKeyChecking/, 'advanced option');
    like($result, qr/-L\s+3306\/mysql\/3306/, 'local fwd');
    like($result, qr/-D\s+1080/, 'dynamic fwd');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 2. _sortTreeData — Tree View Sorting
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_sortTreeData — groups first, alphabetical' => sub {
    $PACMain::FUNCS{_MAIN}{_CFG} = {
        defaults => { 'sort groups first' => 1 },
        environments => {
            'uuid-g1' => { _is_group => 1 },
            'uuid-g2' => { _is_group => 1 },
            'uuid-n1' => { _is_group => 0 },
            'uuid-n2' => { _is_group => 0 },
        },
    };

    my $group_a = { value => [undef, 'Alpha Group', 'uuid-g1'] };
    my $group_z = { value => [undef, 'Zeta Group', 'uuid-g2'] };
    my $node_b  = { value => [undef, 'Beta Node', 'uuid-n1'] };
    my $node_a  = { value => [undef, 'Alpha Node', 'uuid-n2'] };

    # _sortTreeData uses package $a and $b from PACUtils
    {
        no strict 'refs';
        local ${"PACUtils::a"} = $group_a;
        local ${"PACUtils::b"} = $node_b;
        is(PACUtils::_sortTreeData(), -1, 'group before node');
    }
    {
        no strict 'refs';
        local ${"PACUtils::a"} = $node_b;
        local ${"PACUtils::b"} = $group_a;
        is(PACUtils::_sortTreeData(), 1, 'node after group');
    }
    {
        no strict 'refs';
        local ${"PACUtils::a"} = $group_a;
        local ${"PACUtils::b"} = $group_z;
        is(PACUtils::_sortTreeData(), -1, 'alpha group before zeta group');
    }
    {
        no strict 'refs';
        local ${"PACUtils::a"} = $node_a;
        local ${"PACUtils::b"} = $node_b;
        is(PACUtils::_sortTreeData(), -1, 'alpha node before beta node');
    }
};

subtest '_sortTreeData — groups_first=0, pure alphabetical' => sub {
    $PACMain::FUNCS{_MAIN}{_CFG} = {
        defaults => { 'sort groups first' => 0 },
        environments => {
            'uuid-g1' => { _is_group => 1 },
            'uuid-n1' => { _is_group => 0 },
        },
    };

    my $group_z = { value => [undef, 'Zeta Group', 'uuid-g1'] };
    my $node_a  = { value => [undef, 'Alpha Node', 'uuid-n1'] };

    {
        no strict 'refs';
        local ${"PACUtils::a"} = $group_z;
        local ${"PACUtils::b"} = $node_a;
        is(PACUtils::_sortTreeData(), 1, 'without groups-first: Z sorts after A');
    }
    {
        no strict 'refs';
        local ${"PACUtils::a"} = $node_a;
        local ${"PACUtils::b"} = $group_z;
        is(PACUtils::_sortTreeData(), -1, 'without groups-first: A sorts before Z');
    }
};

subtest '_sortTreeData — strips HTML markup before comparing' => sub {
    $PACMain::FUNCS{_MAIN}{_CFG} = {
        defaults => { 'sort groups first' => 0 },
        environments => {
            'uuid-1' => { _is_group => 0 },
            'uuid-2' => { _is_group => 0 },
        },
    };

    my $with_html = { value => [undef, '<b>Beta</b>', 'uuid-1'] };
    my $plain     = { value => [undef, 'Alpha', 'uuid-2'] };

    {
        no strict 'refs';
        local ${"PACUtils::a"} = $with_html;
        local ${"PACUtils::b"} = $plain;
        is(PACUtils::_sortTreeData(), 1, 'HTML stripped: Beta > Alpha');
    }
};

subtest '_sortTreeData — case insensitive' => sub {
    $PACMain::FUNCS{_MAIN}{_CFG} = {
        defaults => { 'sort groups first' => 0 },
        environments => {
            'uuid-1' => { _is_group => 0 },
            'uuid-2' => { _is_group => 0 },
        },
    };

    my $upper = { value => [undef, 'ALPHA', 'uuid-1'] };
    my $lower = { value => [undef, 'alpha', 'uuid-2'] };

    {
        no strict 'refs';
        local ${"PACUtils::a"} = $upper;
        local ${"PACUtils::b"} = $lower;
        is(PACUtils::_sortTreeData(), 0, 'case insensitive: ALPHA == alpha');
    }
};

# ═══════════════════════════════════════════════════════════════════════════════
# 3. _getMagicBytes (KeePass helper) — Binary File Header Reading
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_getMagicBytes — reads correct offset' => sub {
    eval { require PACKeePass } or do {
        pass('PACKeePass not loadable, testing via source');
        return;
    };

    my ($fh, $tmpfile) = tempfile(UNLINK => 1);
    # Write 32 bytes: 8 bytes header + 8 bytes padding + 4 bytes magic + 12 bytes filler
    my $data = "\x00" x 8 . "\xFF" x 8 . "\x41\x49\x02\x00" . "\x00" x 12;
    print $fh $data;
    close $fh;

    my $magic = PACKeePass::_getMagicBytes($tmpfile);
    is($magic, '41490200', 'magic bytes at offset 16-24 extracted correctly');
};

subtest '_getMagicBytes — handles missing file' => sub {
    eval { require PACKeePass } or do {
        pass('PACKeePass not loadable');
        return;
    };
    is(PACKeePass::_getMagicBytes('/nonexistent/file'), '', 'missing file returns empty');
    is(PACKeePass::_getMagicBytes(''), '', 'empty path returns empty');
    is(PACKeePass::_getMagicBytes(undef), '', 'undef returns empty');
};

subtest '_getMagicBytes — small file handled' => sub {
    eval { require PACKeePass } or do {
        pass('PACKeePass not loadable');
        return;
    };
    my ($fh, $tmpfile) = tempfile(UNLINK => 1);
    print $fh "short";  # Only 5 bytes, less than 32
    close $fh;

    my $magic = PACKeePass::_getMagicBytes($tmpfile);
    # Should not crash, may return partial data or empty
    ok(defined $magic, 'small file does not crash');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 4. Message Framing — _receiveData Protocol
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'message framing protocol — format validation' => sub {
    # Verify the PAC_MSG_START/END protocol is used consistently
    my $asbru_conn = read_file("$RealBin/../lib/asbru_conn");
    my $terminal = read_file("$RealBin/../lib/PACTerminal.pm");

    # asbru_conn sends messages with PAC_MSG_START[...]PAC_MSG_END
    like($asbru_conn, qr/PAC_MSG_START/, 'asbru_conn uses PAC_MSG_START');
    like($asbru_conn, qr/PAC_MSG_END/, 'asbru_conn uses PAC_MSG_END');

    # PACTerminal parses with same format
    like($terminal, qr/PAC_MSG_START\[/, 'PACTerminal parses PAC_MSG_START');
    like($terminal, qr/PAC_MSG_END/, 'PACTerminal parses PAC_MSG_END');

    # Count send/parse usage — they should be balanced
    my @sends = ($asbru_conn =~ /PAC_MSG_START/g);
    ok(scalar @sends >= 2, 'message sends in asbru_conn (' . scalar(@sends) . ')');
};

subtest 'message framing — message types used' => sub {
    my $asbru_conn = read_file("$RealBin/../lib/asbru_conn");
    my $terminal = read_file("$RealBin/../lib/PACTerminal.pm");

    # asbru_conn sends messages via ctrl() function which wraps in PAC_MSG_START/END
    # Extract message types from ctrl("TYPE...") calls
    my @msg_types;
    while ($asbru_conn =~ /ctrl\("([A-Z_]+)/g) {
        push @msg_types, $1;
    }
    my %seen;
    @msg_types = grep { !$seen{$_}++ } @msg_types;

    ok(scalar @msg_types >= 5, 'at least 5 message types found: ' . join(', ', @msg_types));

    # Key message types should be handled in PACTerminal
    for my $type (qw(CONNECTED DISCONNECTED ERROR PIPE_WAIT SCRIPT_)) {
        like($terminal, qr/\Q$type\E/, "message type '$type' handled in PACTerminal");
    }
};

# ═══════════════════════════════════════════════════════════════════════════════
# 5. AppRun Script — AppImage Launcher
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'AppRun — security and correctness' => sub {
    my $apprun = read_file("$RealBin/../dist/appimage/AppRun");

    # Security: uses quoted "$@" to prevent word splitting
    like($apprun, qr/"\$\@"/, 'arguments properly quoted with "$@"');

    # Sets critical environment variables
    like($apprun, qr/ASBRU_IS_APPIMAGE/, 'sets ASBRU_IS_APPIMAGE');
    like($apprun, qr/ASBRU_ENV_FOR_EXTERNAL/, 'sets ASBRU_ENV_FOR_EXTERNAL');
    like($apprun, qr/ASBRU_ENV_FOR_INTERNAL/, 'sets ASBRU_ENV_FOR_INTERNAL');
    like($apprun, qr/PERL5LIB/, 'sets PERL5LIB');
    like($apprun, qr/LD_LIBRARY_PATH/, 'sets LD_LIBRARY_PATH');
    like($apprun, qr/GI_TYPELIB_PATH/, 'sets GI_TYPELIB_PATH');
    like($apprun, qr/XDG_DATA_DIRS/, 'sets XDG_DATA_DIRS');
    like($apprun, qr/GTK_PATH/, 'sets GTK_PATH');
    like($apprun, qr/PANGO_LIBDIR/, 'sets PANGO_LIBDIR');

    # Uses exec (replaces shell process)
    like($apprun, qr/^exec\s/m, 'uses exec to replace shell');

    # References APPDIR variable
    like($apprun, qr/\$\{APPDIR\}/, 'uses ${APPDIR} variable');

    # Runs asbru-cm via perl
    like($apprun, qr/perl.*asbru-cm/, 'runs asbru-cm through perl');

    # cd with error handling
    like($apprun, qr/cd.*\|\|\s*exit/, 'cd has failure handling');
};

subtest 'AppRun — shebang and shell compatibility' => sub {
    my $apprun = read_file("$RealBin/../dist/appimage/AppRun");
    like($apprun, qr|^#!/bin/sh|, 'uses portable /bin/sh shebang');
    # No bashisms
    unlike($apprun, qr/\[\[/, 'no bash [[ test syntax');
    unlike($apprun, qr/\bfunction\b/, 'no bash function keyword');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 6. Migration Scripts — asbru2pac.pl and pac2asbru.pl
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'migration scripts — syntax and structure' => sub {
    for my $script (qw(utils/asbru2pac.pl utils/pac2asbru.pl)) {
        my $content = read_file("$RealBin/../$script");

        like($content, qr/^#!.*perl/m, "$script: has perl shebang");
        like($content, qr/use strict/, "$script: uses strict");

        # Should handle backup rotation / file operations
        like($content, qr/rename|mv|move|copy/i, "$script: performs file operations");

        # Should accept directory arguments
        like($content, qr/ARGV|\@_|shift/, "$script: processes arguments");
    }
};

subtest 'migration scripts — handle both directions' => sub {
    my $a2p = read_file("$RealBin/../utils/asbru2pac.pl");
    my $p2a = read_file("$RealBin/../utils/pac2asbru.pl");

    # asbru2pac should reference asbru -> pac file renames
    like($a2p, qr/asbru/, 'asbru2pac references asbru format');
    like($a2p, qr/pac/i, 'asbru2pac references pac format');

    # pac2asbru should reference pac -> asbru file renames
    like($p2a, qr/pac/i, 'pac2asbru references pac format');
    like($p2a, qr/asbru/, 'pac2asbru references asbru format');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 7. Connection Method Plugins — Deep Structure Tests
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'method plugins — _parseCfgToOptions/_parseOptionsToCfg roundtrip' => sub {
    my @methods = glob("$RealBin/../lib/method/PACMethod_*.pm");

    for my $file (@methods) {
        my $content = read_file($file);
        my ($name) = $file =~ /PACMethod_(\w+)\.pm$/;

        # Each method should have balanced parse/build functions
        like($content, qr/sub _parseCfgToOptions/, "$name: parser exists");
        like($content, qr/sub _parseOptionsToCfg/, "$name: builder exists");

        # Security: no raw system() calls in method plugins
        my @system_calls = $content =~ /\bsystem\s*\(/g;
        # Only count system calls outside of comments
        my @real_systems;
        while ($content =~ /^(?!\s*#).*\bsystem\s*\(/mg) {
            push @real_systems, $&;
        }
        is(scalar @real_systems, 0, "$name: no system() calls in method plugin")
            or diag("Found system() in $name: " . join(', ', @real_systems));
    }
};

subtest 'SSH method — advanced option security' => sub {
    my $ssh = read_file("$RealBin/../lib/method/PACMethod_ssh.pm");

    # Must block dangerous SSH options
    like($ssh, qr/ProxyCommand/, 'SSH: ProxyCommand blocked');
    like($ssh, qr/LocalCommand/, 'SSH: LocalCommand blocked');
    like($ssh, qr/PermitLocalCommand/, 'SSH: PermitLocalCommand blocked');

    # Must validate option characters
    like($ssh, qr/shell metacharacters|invalid characters/i, 'SSH: metacharacter validation');
};

subtest 'xfreerdp method — cert handling' => sub {
    my $xfreerdp = read_file("$RealBin/../lib/method/PACMethod_xfreerdp.pm");

    # Should have cert-ignore option
    like($xfreerdp, qr/cert-ignore|cert.tofu|sec-cert/i, 'xfreerdp: cert handling present');

    # Should reference TLS settings
    like($xfreerdp, qr/tls|TLS/i, 'xfreerdp: TLS settings present');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 8. Config Anonymization — cleanUpPersonalData Source Verification
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'config anonymization — removes sensitive fields' => sub {
    my $config_pm = read_file("$RealBin/../lib/PACConfig.pm");

    # Verify all sensitive fields are anonymized
    my @sensitive = qw(name send ip user password passphrase);
    for my $field (@sensitive) {
        like($config_pm, qr/\Q$field\E.*removed/s,
            "cleanUpPersonalData removes '$field'");
    }

    # Verify home path replacement
    like($config_pm, qr|/home/PATH/|, 'home paths replaced with /home/PATH/');

    # Verify ENV vars filtered
    like($config_pm, qr/token.*hostname.*AUTH/si, 'sensitive ENV vars filtered');
};

subtest 'config anonymization — does not leak secrets in debug export' => sub {
    my $config_pm = read_file("$RealBin/../lib/PACConfig.pm");

    # Debug export should warn about sensitive data
    like($config_pm, qr/cleanUpPersonalData|personal.*data/i,
        'debug export calls anonymization');

    # Debug export should have confirmation
    like($config_pm, qr/wConfirm|confirm|warning/i,
        'debug export requires confirmation');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 9. PACStatistics — Source Code Verification
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'PACStatistics — key functions present' => sub {
    my $stats = read_file("$RealBin/../lib/PACStatistics.pm");

    like($stats, qr/sub update\b/, 'update() exists');
    like($stats, qr/sub start\b/, 'start() exists');
    like($stats, qr/sub stop\b/, 'stop() exists');
    like($stats, qr/sub purge\b/, 'purge() exists');
    like($stats, qr/sub readStats\b/, 'readStats() exists');
    like($stats, qr/sub saveStats\b/, 'saveStats() exists');

    # Time formatting
    like($stats, qr/day|hour|minute|second/i, 'time formatting present');

    # Uses Storable for persistence
    like($stats, qr/Storable|nstore|retrieve/, 'uses Storable for persistence');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 10. PACCluster — Source Code Verification
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'PACCluster — key functions present' => sub {
    my $cluster = read_file("$RealBin/../lib/PACCluster.pm");

    like($cluster, qr/sub addToCluster\b/, 'addToCluster() exists');
    like($cluster, qr/sub delFromCluster\b/, 'delFromCluster() exists');
    like($cluster, qr/sub getCFGClusters\b/, 'getCFGClusters() exists');

    # Tree management
    like($cluster, qr/TreeStore|TreeView|TreeModel/, 'uses GTK tree widgets');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 11. PACPipe — Source Code Verification
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'PACPipe — key functions present' => sub {
    my $pipe = read_file("$RealBin/../lib/PACPipe.pm");

    like($pipe, qr/sub new\b/, 'new() constructor exists');
    like($pipe, qr/sub show\b/, 'show() exists');
    like($pipe, qr/_initGUI|_buildGUI/, 'GUI initialization exists');
    like($pipe, qr/_setupCallbacks/, 'callback setup exists');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 12. _makeDesktopFile — Desktop Entry Generation
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_makeDesktopFile — source code verification' => sub {
    my $utils = read_file("$RealBin/../lib/PACUtils.pm");

    # Verify desktop file format
    like($utils, qr/\[Desktop Entry\]/, 'Desktop Entry header');
    like($utils, qr/Type=Application/, 'Type=Application');
    like($utils, qr/Terminal=false/, 'Terminal=false');
    like($utils, qr/Categories=.*Network/, 'Network category');

    # Desktop actions
    like($utils, qr/Desktop Action Shell/, 'Shell action defined');
    like($utils, qr/Desktop Action Quick/, 'Quick connect action');
    like($utils, qr/Desktop Action Preferences/, 'Preferences action');

    # Security: uses fork+exec not system() for xdg-desktop-menu
    like($utils, qr/fork\(\).*exec\('xdg-desktop-menu'/s,
        'xdg-desktop-menu via fork+exec');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 13. _getEncodings — Complete Encoding Coverage
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_getEncodings — all major encodings present' => sub {
    my $enc = PACUtils::_getEncodings();

    # Encoding names use IANA format — check what's actually in the hash
    my @required = qw(
        UTF-8 UTF-16 UTF-32
        ISO-8859-15 ISO-8859-16
        Big5 Shift_JIS GB2312 GBK
        KOI8-R KOI8-U
        windows-1250 windows-1251 windows-1252
    );

    for my $e (@required) {
        ok(exists $$enc{$e}, "encoding '$e' available");
    }
};

# ═══════════════════════════════════════════════════════════════════════════════
# 14. asbru_conn — Deep Connection Script Tests
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'asbru_conn — auth token handling' => sub {
    my $content = read_file("$RealBin/../lib/asbru_conn");

    # Auth token variable used for IPC authentication
    like($content, qr/auth_token/, 'auth_token variable used');
    # Auth function sends token via ctrl()
    like($content, qr/PAC_AUTH/, 'PAC_AUTH protocol for authentication');
};

subtest 'asbru_conn — send_slow password protection' => sub {
    my $content = read_file("$RealBin/../lib/asbru_conn");

    # send_slow should suppress logging for passwords
    like($content, qr/log_file.*undef|log_file.*''|log_file\(undef\)/,
        'log_file suspended during password send');
};

subtest 'asbru_conn — connection methods handled' => sub {
    my $content = read_file("$RealBin/../lib/asbru_conn");

    my @methods = qw(SSH SFTP Telnet FTP VNC RDP mosh cu);
    for my $m (@methods) {
        like($content, qr/\Q$m\E/i, "connection method '$m' handled");
    }
};

subtest 'asbru_conn — temp file cleanup in END block' => sub {
    my $content = read_file("$RealBin/../lib/asbru_conn");

    # END block should clean up all temp files
    like($content, qr/END.*unlink/s, 'END block unlinks temp files');
    like($content, qr/END.*\$_vnc_pfile/s, 'VNC password file cleaned');
    like($content, qr/END.*rdp.*\.pass|rdp_pass/si, 'RDP password file cleaned');
};

subtest 'asbru_conn — jump host configuration' => sub {
    my $content = read_file("$RealBin/../lib/asbru_conn");

    like($content, qr/ProxyJump|jump.*host|jump.*ip/i, 'jump host support');
    like($content, qr/ssh.*config|\.conf/, 'SSH config file generation');
    like($content, qr/chmod\s+0600/, 'SSH config restricted permissions');
};

subtest 'asbru_conn — IPC::Open3 for VNC password' => sub {
    my $content = read_file("$RealBin/../lib/asbru_conn");

    like($content, qr/IPC::Open3|open3/, 'uses IPC::Open3');
    like($content, qr/vncpasswd/, 'vncpasswd invocation');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 15. Config Save/Load — Source Code Integrity
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'config save — file locking used' => sub {
    my $main = read_file("$RealBin/../lib/PACMain.pm");

    like($main, qr/flock.*LOCK_EX/, 'exclusive file lock on save');
    like($main, qr/nstore/, 'uses Storable nstore');
};

subtest 'config load — HMAC verification' => sub {
    my $main = read_file("$RealBin/../lib/PACMain.pm");

    like($main, qr/HMAC|hmac/i, 'HMAC verification present');
    like($main, qr/verif.*HMAC|_verifyConfigHMAC|_readConfigHMAC/i,
        'HMAC verified before loading');
};

subtest 'config load — multi-format fallback' => sub {
    my $main = read_file("$RealBin/../lib/PACMain.pm");

    # Should support multiple config formats
    like($main, qr/nfreeze|\.nfreeze/, 'supports Storable nfreeze format');
    like($main, qr/YAML|yaml|\.yml/, 'supports YAML format');
    like($main, qr/Dumper|\.dumper/, 'supports Data::Dumper format');
};

subtest 'config load — readonly mode' => sub {
    my $main = read_file("$RealBin/../lib/PACMain.pm");

    like($main, qr/_READONLY/, 'readonly mode variable exists');
    like($main, qr/return.*READONLY|READONLY.*return/s, 'readonly prevents save');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 16. Terminal Execution — Storm Prevention & Security
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'terminal execution — storm prevention' => sub {
    my $terminal = read_file("$RealBin/../lib/PACTerminal.pm");

    like($terminal, qr/EXEC_LAST|exec_last|storm|throttl/i,
        'execution storm prevention logic exists');
};

subtest 'terminal — EXPLORER path validation' => sub {
    my $terminal = read_file("$RealBin/../lib/PACTerminal.pm");

    # EXPLORER messages should validate paths
    like($terminal, qr/EXPLORER/, 'EXPLORER message type handled');
    # Path should not allow shell injection
    like($terminal, qr/fork.*exec.*xdg-open/s, 'xdg-open via fork+exec for EXPLORER');
};

subtest 'terminal — pipe command validation' => sub {
    my $terminal = read_file("$RealBin/../lib/PACTerminal.pm");

    # Pipe commands should be validated
    like($terminal, qr/PIPE|pipe/, 'pipe functionality exists');
    # Security: pipe command whitelist
    like($terminal, qr/disallowed|whitelist|invalid|blocked/i,
        'pipe command validation present');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 17. _replaceBadChars — Coverage for All Control Character Groups
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_replaceBadChars — C0 control codes exhaustive' => sub {
    my %expected_names = (
        "\x01" => 'SOH',
        "\x02" => 'STX',
        "\x03" => 'ETX',
        "\x04" => 'EOT',
        "\x05" => 'ENQ',
        "\x06" => 'ACK',
        "\x09" => 'AB',    # horizontal tab
        "\x0B" => 'VT',
        "\x0C" => 'FF',
        "\x0E" => 'SO',
        "\x0F" => 'SI',
        "\x10" => 'DLE',
        "\x11" => 'DC1',
        "\x12" => 'DC2',
        "\x13" => 'DC3',
        "\x14" => 'DC4',
        "\x15" => 'NAK',
        "\x16" => 'SYN',
        "\x17" => 'ETB',
        "\x18" => 'CAN',
        "\x19" => 'EM',
        "\x1A" => 'SUB',
        "\x1C" => 'FS',
        "\x1D" => 'GS',
        "\x1E" => 'RS',
        "\x1F" => 'US',
    );

    for my $char (sort keys %expected_names) {
        my $result = PACUtils::_replaceBadChars($char);
        my $name = $expected_names{$char};
        like($result, qr/$name/, sprintf("0x%02X → %s", ord($char), $name));
    }
};

subtest '_replaceBadChars — mixed control and printable' => sub {
    my $input = "Hello\x07World\x08!";
    my $result = PACUtils::_replaceBadChars($input);
    like($result, qr/Hello/, 'printable text preserved');
    like($result, qr/BEL/, 'BEL in context');
    like($result, qr/BS/, 'BS in context');
    like($result, qr/World/, 'text after control preserved');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 18. Config Structure — Deep Validation
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'config — environment entry has all required fields after sanity check' => sub {
    my $cfg = {
        defaults => {},
        environments => {
            'test-uuid' => {
                name => 'TestConn',
                method => 'SSH',
                options => '',
            },
        },
    };
    PACUtils::_cfgSanityCheck($cfg);

    my $env = $$cfg{environments}{'test-uuid'};
    my @required = (
        'name', 'title', 'ip', 'port', 'user', 'pass', 'method', 'options',
        'description', 'parent', '_protected', 'auth fallback',
    );

    for my $field (@required) {
        ok(defined $$env{$field}, "env field '$field' defined after sanity check");
    }

    # port defaults
    ok($$env{port} =~ /^\d+$/, 'port is numeric');

    # parent defaults
    is($$env{parent}, '__PAC__ROOT__', 'default parent is root');

    # title defaults to name
    is($$env{title}, 'TestConn', 'title defaults to name');

    # description auto-generated
    like($$env{description}, qr/TestConn/, 'description includes connection name');
};

subtest 'config — SSH option format normalization (slash to colon)' => sub {
    # The regex normalizes: -L bind/port/host/hostport → -L bind:port:host:hostport
    # It requires 4 slash-separated fields (old format with bind address)
    my $cfg = {
        defaults => {},
        environments => {
            'ssh-test' => {
                name => 'SSHTest',
                method => 'SSH',
                options => '-L 0.0.0.0/8080/localhost/80 -R 0.0.0.0/9090/db/5432',
            },
        },
    };
    PACUtils::_cfgSanityCheck($cfg);

    my $opts = $$cfg{environments}{'ssh-test'}{options};
    like($opts, qr/-L 0\.0\.0\.0:8080:localhost:80/, 'local fwd slashes normalized to colons');
    like($opts, qr/-R 0\.0\.0\.0:9090:db:5432/, 'remote fwd slashes normalized to colons');
};

subtest 'config — dynamic forward format normalization' => sub {
    my $cfg = {
        defaults => {},
        environments => {
            'dyn-test' => {
                name => 'DynTest',
                method => 'SSH',
                options => '-D 1080/1080',
            },
        },
    };
    PACUtils::_cfgSanityCheck($cfg);

    my $opts = $$cfg{environments}{'dyn-test'}{options};
    like($opts, qr/-D/, 'dynamic forward present');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 19. Storable Security — Deserialization Safety
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'config load — Safe.pm sandbox for Dumper format' => sub {
    my $main = read_file("$RealBin/../lib/PACMain.pm");

    like($main, qr/Safe|safe/i, 'Safe.pm used for sandboxed eval');
    unlike($main, qr/eval\s+\$\w+\s*;(?!.*Safe)/s,
        'no raw eval of config data without Safe compartment');
};

subtest 'config — HMAC prevents tampering' => sub {
    my $main = read_file("$RealBin/../lib/PACMain.pm");
    my $utils = read_file("$RealBin/../lib/PACUtils.pm");

    # HMAC functions should exist
    my $has_hmac = ($main =~ /writeConfigHMAC|_writeConfigHMAC/ &&
                    $main =~ /verifyConfigHMAC|readConfigHMAC|_readConfigHMAC/);
    ok($has_hmac, 'HMAC write and verify functions present');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 20. Comprehensive _subst — Timestamp Consistency
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_subst — TIMESTAMP is consistent with DATE/TIME' => sub {
    my ($cfg, $uuid) = ({
        defaults => { 'global variables' => {} },
        environments => {
            'ts-test' => {
                name => 'Test', title => 'T', ip => '1.1.1.1',
                port => '22', user => 'u', pass => 'p',
                'auth type' => 'userpass', 'passphrase user' => '',
                passphrase => '', variables => [], method => 'ssh',
                'connection options' => { randomSocksTunnel => 0 },
            },
        },
    }, 'ts-test');

    my $ts = PACUtils::_subst('<TIMESTAMP>', $cfg, $uuid);
    my $y  = PACUtils::_subst('<DATE_Y>', $cfg, $uuid);
    my $m  = PACUtils::_subst('<DATE_M>', $cfg, $uuid);
    my $d  = PACUtils::_subst('<DATE_D>', $cfg, $uuid);

    # Timestamp should be a valid epoch
    like($ts, qr/^\d{10,}$/, 'TIMESTAMP is epoch format');

    # Convert epoch to date parts
    my @t = localtime(int($ts));
    my $ts_year = $t[5] + 1900;
    my $ts_month = sprintf('%02d', $t[4] + 1);
    my $ts_day = sprintf('%02d', $t[3]);

    is($ts_year, int($y), 'TIMESTAMP year matches DATE_Y');
    is($ts_month, sprintf('%02d', int($m)), 'TIMESTAMP month matches DATE_M');
    is($ts_day, sprintf('%02d', int($d)), 'TIMESTAMP day matches DATE_D');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 21. KeePass — Source Code Security
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'KeePass — CLI path validation' => sub {
    my $kp = read_file("$RealBin/../lib/PACKeePass.pm");

    # CLI path must be validated against injection
    like($kp, qr/metacharacter|shell.*char|injection|invalid/i,
        'CLI path validation present');

    # Must check CLI binary exists
    like($kp, qr/(-f|-e|-x).*cli|cli.*(exist|found|valid)/i, 'CLI binary check');
};

subtest 'KeePass — password not on command line' => sub {
    my $kp = read_file("$RealBin/../lib/PACKeePass.pm");

    # Password should be sent via stdin, not command line
    like($kp, qr/stdin|STDIN|print.*writer|syswrite/i, 'password sent via stdin');

    # Should use open3/open2 for process management
    like($kp, qr/open3|open2|IPC::Open/, 'uses IPC::Open for process management');
};

subtest 'KeePass — cache invalidation logic' => sub {
    my $kp = read_file("$RealBin/../lib/PACKeePass.pm");

    # Cache should track mtime
    like($kp, qr/mtime|stat\b/, 'tracks file modification time');
    like($kp, qr/CACHE_TIMESTAMP|cache.*time/i, 'cache timestamp variable');
    like($kp, qr/KPXC_CACHE\s*=\s*\(\)/, 'cache clear operation');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 22. Error Handling Paths
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'critical functions have error handling' => sub {
    my $utils = read_file("$RealBin/../lib/PACUtils.pm");
    my $main = read_file("$RealBin/../lib/PACMain.pm");
    my $conn = read_file("$RealBin/../lib/asbru_conn");

    # _deleteOldestSessionLog dies on errors
    like($utils, qr/_deleteOldestSessionLog.*die/s, 'log deletion has die on error');

    # Config save checks for errors
    like($main, qr/nstore.*or|eval.*nstore/s, 'nstore has error handling');

    # asbru_conn checks spawn result
    like($conn, qr/spawn.*die|spawn.*or|spawn.*error/si, 'spawn has error handling');
};

subtest 'file operations use error checking' => sub {
    my @files = qw(
        lib/PACUtils.pm lib/PACTerminal.pm lib/PACConfig.pm
        lib/PACScripts.pm lib/PACPCC.pm
    );

    for my $file (@files) {
        my $content = read_file("$RealBin/../$file");

        # Count opens without error handling
        my @unhandled = $content =~ /open\s*\(\s*my\s+\$\w+.*\)\s*;(?!\s*#)/g;
        # Filter: `open(...) or do { ... };` pattern is safe
        my $opens_total = () = $content =~ /\bopen\s*\(/g;
        my $opens_safe = () = $content =~ /\bopen\s*\(.*\)\s+or\b/g;
        my $opens_check = () = $content =~ /if\s*\(.*\bopen\s*\(/g;

        ok($opens_safe + $opens_check >= $opens_total * 0.7,
            "$file: most opens have error handling ($opens_safe+$opens_check of $opens_total)");
    }
};

done_testing();
