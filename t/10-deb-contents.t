#!/usr/bin/perl
use strict;
use warnings;
use Test::More;

# Validates a built .deb package.
# Expects DEB_FILE env var pointing to the .deb, or skips.

my $deb = $ENV{DEB_FILE} // '';

if (!$deb) {
    # Try to find it in common locations
    ($deb) = glob('/build/asbru-plus_*.deb') if !$deb;
    ($deb) = glob('/output/asbru-plus_*.deb') if !$deb;
}

unless ($deb && -f $deb) {
    plan skip_all => 'DEB_FILE not set or not found — run inside build-deb container';
}

# Read version dynamically from PACUtils.pm
my $version = do {
    my $v;
    open my $f, '<', 'lib/PACUtils.pm' or die "Cannot open lib/PACUtils.pm: $!";
    while (<$f>) { if (/^\s*our\s+\$APPVERSION\s*=\s*'([^']+)'/) { $v = $1; last } }
    close $f;
    $v or die "Could not find \$APPVERSION in lib/PACUtils.pm";
};

plan tests => 16;

# --- Basic file check ---
ok(-f $deb, "DEB file exists: $deb");
ok(-s $deb > 0, 'DEB file is not empty');

# --- dpkg-deb --info ---
my $info = `dpkg-deb --info "$deb" 2>&1`;
is($?, 0, 'dpkg-deb --info exits cleanly');

like($info, qr/Package:\s+asbru-plus\b/, 'Package name is asbru-plus');
like($info, qr/Architecture:\s+all\b/,   'Architecture is all');
like($info, qr/Version:\s+\Q$version\E/, "Version is $version");
like($info, qr/Maintainer:/,             'Maintainer field present');
like($info, qr/Depends:.*perl/i,         'Depends includes perl');

# Replaces/Conflicts asbru-cm (upgrade path)
like($info, qr/Replaces:.*asbru-cm/,   'Replaces: asbru-cm');
like($info, qr/Conflicts:.*asbru-cm/,  'Conflicts: asbru-cm');

# --- dpkg-deb --contents ---
my $contents = `dpkg-deb --contents "$deb" 2>&1`;
is($?, 0, 'dpkg-deb --contents exits cleanly');

like($contents, qr|opt/asbru/asbru-cm\b|,          'Main binary in package');
like($contents, qr|opt/asbru/lib/|,                 'lib/ directory in package');
like($contents, qr|opt/asbru/res/|,                 'res/ directory in package');
like($contents, qr|usr/share/applications/|,        '.desktop file directory in package');
like($contents, qr|usr/share/man/man1/|,            'man page in package');
