#!/usr/bin/perl
use strict;
use warnings;
use Test::More;

# Validates a built .rpm package.
# Expects RPM_FILE env var pointing to the .rpm, or skips.

my $rpm = $ENV{RPM_FILE} // '';

unless ($rpm && -f $rpm) {
    plan skip_all => 'RPM_FILE not set or not found — run inside build-rpm container';
}

plan tests => 14;

ok(-f $rpm,      "RPM file exists: $rpm");
ok(-s $rpm > 0,  'RPM file is not empty');

# --- rpm -qip (info) ---
my $info = `rpm -qip "$rpm" 2>&1`;
is($?, 0, 'rpm -qip exits cleanly');

like($info, qr/Name\s*:\s*asbru-plus\b/,   'Package name is asbru-plus');
like($info, qr/Architecture\s*:\s*noarch/, 'Architecture is noarch');
like($info, qr/Version\s*:\s*6\.5\.0/,     'Version is 6.5.0');
like($info, qr/License\s*:\s*GPLv3\+/,     'License is GPLv3+');
like($info, qr/Obsoletes\s*:.*asbru-cm/i,  'Obsoletes: asbru-cm');

# --- rpm -qlp (file list) ---
my $files = `rpm -qlp "$rpm" 2>&1`;
is($?, 0, 'rpm -qlp exits cleanly');

like($files, qr|/usr/bin/asbru-plus|,              'Binary /usr/bin/asbru-plus in package');
like($files, qr|/usr/share/asbru-plus/lib/|,       'lib/ directory in package');
like($files, qr|/usr/share/asbru-plus/res/|,       'res/ directory in package');
like($files, qr|/usr/share/applications/|,         '.desktop file in package');
like($files, qr|/usr/share/man/man1/|,             'man page in package');
