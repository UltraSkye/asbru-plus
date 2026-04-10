#!/usr/bin/perl
# t/21-dump-uuid-redaction.t
# Static check: --dump-uuid must redact pass/passphrase/expect[hidden]/
# variables[hide] by default and only reveal them when --with-secrets
# is also passed.
use strict;
use warnings;
use Test::More tests => 8;
use FindBin qw($RealBin);

my $main_pm = "$RealBin/../lib/PACMain.pm";
ok(-r $main_pm, 'PACMain.pm is readable');

open(my $fh, '<', $main_pm) or die "open: $!";
local $/;
my $src = <$fh>;
close $fh;

# Locate the --dump-uuid block
my ($block) = $src =~ /(--dump-uuid=.{1,3000}exit 0;)/s;
ok(defined $block, '--dump-uuid block found');

like($block, qr/--with-secrets/,
    '--dump-uuid recognises --with-secrets opt-in flag');

like($block, qr/REDACTED/,
    '--dump-uuid replaces secret fields with REDACTED placeholder');

like($block, qr/dclone/,
    '--dump-uuid clones the node before redacting (no in-place mutation)');

like($block, qr/qw\(\s*pass\s+passphrase\s*\)/,
    '--dump-uuid redacts pass and passphrase fields');

like($block, qr/\$node->\{expect\}.*hidden/s,
    '--dump-uuid iterates expect entries with hidden flag');

like($block, qr/\$node->\{variables\}.*hide/s,
    '--dump-uuid iterates variables with hide flag');
