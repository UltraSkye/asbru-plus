#!/usr/bin/perl
# t/18-storable-rce-gate.t
# Verify the audit-time critical fixes for Storable deserialization safety
# stay in place: _safe_retrieve disables Eval/Deparse, _verifyConfigHMAC
# rejects missing sidecar when a master password is set, and constant-time
# compare is used.
use strict;
use warnings;
use Test::More tests => 12;
use FindBin qw($RealBin);

my $main_pm = "$RealBin/../lib/PACMain.pm";
ok(-r $main_pm, 'PACMain.pm is readable');

open(my $fh, '<', $main_pm) or die "open $main_pm: $!";
local $/;
my $src = <$fh>;
close $fh;

# C1: _safe_retrieve helper exists with the necessary local pragmas
like($src, qr/sub _safe_retrieve/,
    'PACMain defines _safe_retrieve wrapper');
like($src, qr/local \$Storable::Eval\s*=\s*0/,
    '_safe_retrieve disables Storable::Eval');
like($src, qr/local \$Storable::Deparse\s*=\s*0/,
    '_safe_retrieve disables Storable::Deparse');

# Bare retrieve() must not be used in _readConfiguration paths
my @bare = ($src =~ /^\s*\$\$self\{_CFG\}\s*=\s*retrieve\(/mg);
is(scalar(@bare), 0,
    'no bare retrieve() in _readConfiguration — must go through _safe_retrieve');

# Every config path uses _safe_retrieve
like($src, qr/_safe_retrieve\(\$R_CFG_FILE\)/,
    'remote config retrieved via _safe_retrieve');
like($src, qr/_safe_retrieve\(\$CFG_FILE_NFREEZE\)/,
    'nfreeze retrieved via _safe_retrieve');
like($src, qr/_safe_retrieve\(\$CFG_FILE_FREEZE\)/,
    'legacy freeze retrieved via _safe_retrieve');

# S2: HMAC fail-closed when master password is set
like($src, qr/has a master password set but no HMAC sidecar/,
    'verifyConfigHMAC refuses missing sidecar with master pwd present');

# S20: constant-time compare on HMAC and verifier
like($src, qr/sub _ct_eq/,
    'PACMain has constant-time compare helper');
like($src, qr/_ct_eq\(\$computed/,
    'HMAC compare is constant-time');

# S8: prctl PR_SET_DUMPABLE in entry point
my $entry = "$RealBin/../asbru-cm";
open(my $efh, '<', $entry) or die "open $entry: $!";
local $/;
my $esrc = <$efh>;
close $efh;
like($esrc, qr/PR_SET_DUMPABLE|set_dumpable\(0\)|SYS_prctl/,
    'asbru-cm sets PR_SET_DUMPABLE=0 to block coredumps');
