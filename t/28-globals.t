#!/usr/bin/perl
# t/28-globals.t — PAC::Globals facade for process-wide state hashes.
#
# Verifies:
#   - module loads cleanly with no PACMain/PACScripts present
#   - accessors return hashref aliases (mutations bidirectionally visible)
#   - main_window() / cfg() convenience wrappers handle missing state
#   - public POD is in place

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

# Stub PACMain + PACScripts namespaces BEFORE loading PAC::Globals so the
# accessors have something to alias to. In production these are populated
# by PACMain::new() running first.
BEGIN {
    package PACMain;
    our %FUNCS       = ();
    our %RUNNING     = ();
    our %SOCKS5PORTS = ();

    package PACScripts;
    our %SHARED   = ();
    our %COMMON   = ();
    our %PAC      = ();
    our %TERMINAL = ();
}

require_ok('PAC::Globals');

for my $sub (qw(funcs running socks5_ports shared common main_window cfg)) {
    can_ok('PAC::Globals', $sub);
}

# ── 1. Each accessor returns a hashref ──────────────────────────────
isa_ok(PAC::Globals::funcs(),        'HASH', 'funcs() returns hashref');
isa_ok(PAC::Globals::running(),      'HASH', 'running() returns hashref');
isa_ok(PAC::Globals::socks5_ports(), 'HASH', 'socks5_ports() returns hashref');
isa_ok(PAC::Globals::shared(),       'HASH', 'shared() returns hashref');
isa_ok(PAC::Globals::common(),       'HASH', 'common() returns hashref');

# ── 2. Mutations through facade are visible to legacy readers ───────
PAC::Globals::funcs()->{__test_marker} = 42;
is($PACMain::FUNCS{__test_marker}, 42,
    'PAC::Globals::funcs mutation visible to $PACMain::FUNCS');

$PACMain::RUNNING{__legacy_marker} = 'hi';
is(PAC::Globals::running()->{__legacy_marker}, 'hi',
    'legacy $PACMain::RUNNING mutation visible to PAC::Globals::running');

PAC::Globals::shared()->{__shared_marker} = ['a', 'b'];
is_deeply($PACScripts::SHARED{__shared_marker}, ['a', 'b'],
    'PAC::Globals::shared mutation visible to $PACScripts::SHARED');

# ── 3. Same hashref returned on every call (alias, not copy) ────────
my $r1 = PAC::Globals::funcs();
my $r2 = PAC::Globals::funcs();
is("$r1", "$r2", 'funcs() returns identical reference each call');

# ── 4. main_window() handles missing state gracefully ───────────────
delete $PACMain::FUNCS{_MAIN};
is(PAC::Globals::main_window(), undef, 'main_window() returns undef pre-init');
is(PAC::Globals::cfg(),         undef, 'cfg() returns undef pre-init');

$PACMain::FUNCS{_MAIN} = { _GUI => { main => 'pretend-window' }, _CFG => { foo => 1 } };
is(PAC::Globals::main_window(), 'pretend-window', 'main_window() resolves');
is_deeply(PAC::Globals::cfg(), { foo => 1 }, 'cfg() resolves');

# Cleanup test markers so they don't leak.
delete $PACMain::FUNCS{__test_marker};
delete $PACMain::RUNNING{__legacy_marker};
delete $PACScripts::SHARED{__shared_marker};

# ── 5. POD coverage check (subset of t/27) ──────────────────────────
my $src = do {
    open my $fh, '<', "$RealBin/../lib/PAC/Globals.pm" or die "open: $!";
    local $/;
    <$fh>;
};
like($src, qr/^=head1 NAME/m, 'has =head1 NAME');
like($src, qr/^=head1 PUBLIC API/m, 'has =head1 PUBLIC API');
for my $sub (qw(funcs running socks5_ports shared common main_window cfg)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item for $sub");
}

done_testing();
