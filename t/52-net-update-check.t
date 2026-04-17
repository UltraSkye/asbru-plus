#!/usr/bin/perl
# t/52-net-update-check.t — PAC::Net::UpdateCheck pure version-compare.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::Net::UpdateCheck');
can_ok('PAC::Net::UpdateCheck', $_) for qw(fetch_latest is_newer);

# is_newer — pure version comparison
ok( PAC::Net::UpdateCheck::is_newer('v6.5.1', 'v6.5.0'), '6.5.1 > 6.5.0');
ok( PAC::Net::UpdateCheck::is_newer('v6.6.0', 'v6.5.9'), '6.6.0 > 6.5.9');
ok( PAC::Net::UpdateCheck::is_newer('6.5.1',  '6.5.0'),  'works without leading v');
ok( PAC::Net::UpdateCheck::is_newer('v6.5.1', '6.5.0'),  'mixed v / no-v');
ok(!PAC::Net::UpdateCheck::is_newer('v6.5.0', 'v6.5.0'), '6.5.0 == 6.5.0 not newer');
ok(!PAC::Net::UpdateCheck::is_newer('v6.4.0', 'v6.5.0'), '6.4.0 < 6.5.0 not newer');
ok(!PAC::Net::UpdateCheck::is_newer(undef, 'v6.5.0'),    'undef latest -> false');
ok(!PAC::Net::UpdateCheck::is_newer('v6.5.0', undef),    'undef current -> false');

# REGRESSION: the previous string-compare implementation said
# '6.10.0' is NOT newer than '6.9.0' because '6.1' sorts before '6.9'
# lexically. Real bug: anyone on 6.9 would never see the "update
# available" banner once 6.10+ shipped.
ok( PAC::Net::UpdateCheck::is_newer('v6.10.0', 'v6.9.0'),
    'REGRESSION: 6.10.0 > 6.9.0 (was string-compared as no)');
ok( PAC::Net::UpdateCheck::is_newer('6.10.0', '6.9.0'),
    'REGRESSION: 6.10.0 > 6.9.0 without leading v');
ok( PAC::Net::UpdateCheck::is_newer('10.0.0', '6.5.0'),
    'REGRESSION: 10.0.0 > 6.5.0 (string-compare said no)');
ok( PAC::Net::UpdateCheck::is_newer('6.6.0', '6.5.10'),
    'REGRESSION: 6.6.0 > 6.5.10 (minor wins over patch double-digits)');
ok(!PAC::Net::UpdateCheck::is_newer('6.5.10', '6.6.0'),
    'REGRESSION: 6.5.10 < 6.6.0 (not the other way around)');

# Length normalization: strict-less components zero-padded
ok(!PAC::Net::UpdateCheck::is_newer('6.5',   '6.5.0'),
    '6.5 == 6.5.0 (zero-padded, not newer)');
ok(!PAC::Net::UpdateCheck::is_newer('6.5.0', '6.5'),
    '6.5.0 == 6.5 (zero-padded, not newer)');
ok( PAC::Net::UpdateCheck::is_newer('6.5.1', '6.5'),
    '6.5.1 > 6.5 (with zero-pad)');

# Source-level checks for fetch_latest (network call avoided)
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Net/UpdateCheck.pm" or die "open: $!";
    local $/; <$f>;
};

like($src, qr/HTTP::Tiny/, 'uses HTTP::Tiny');
like($src, qr/timeout => 4/, 'uses 4-second timeout');
like($src, qr{api\.github\.com/repos/UltraSkye/asbru-plus/releases/latest},
    'default URL points at asbru-plus repo');
like($src, qr/"tag_name"\\s\*:\\s\*"\(\[\^"\]\+\)"/,
    'parses tag_name from JSON');
like($src, qr/"html_url"\\s\*:\\s\*"\(\[\^"\]\+\)"/,
    'parses html_url from JSON');

# Fetch returns undef on a guaranteed-bad URL (file:// path)
my $rc = PAC::Net::UpdateCheck::fetch_latest('file:///nonexistent/path');
ok(!defined $rc, 'fetch_latest returns undef on bad URL');

# PACMain wrapper now uses the new module
my $main = do {
    open my $f, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$f>;
};
like($main, qr/PAC::Net::UpdateCheck::fetch_latest/,
    'PACMain calls fetch_latest');
like($main, qr/PAC::Net::UpdateCheck::is_newer/,
    'PACMain calls is_newer');
unlike($main, qr/HTTP::Tiny/,
    'PACMain no longer requires HTTP::Tiny directly (delegated)');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item fetch_latest/m,'POD =item fetch_latest');
like($src, qr/^=item is_newer/m,    'POD =item is_newer');

done_testing();
