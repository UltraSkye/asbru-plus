#!/usr/bin/perl
# t/02-packaging.t — Verify packaging files are consistent and correct
use strict;
use warnings;
use Test::More;
use File::Basename;

# ── Version consistency ───────────────────────────────────────────────────────

my $appversion;
{
    open my $fh, '<', 'lib/PACUtils.pm' or BAIL_OUT("Cannot open lib/PACUtils.pm: $!");
    while (<$fh>) {
        if (/our\s+\$APPVERSION\s*=\s*'([^']+)'/) {
            $appversion = $1;
            last;
        }
    }
    close $fh;
}
ok(defined $appversion, "APPVERSION defined in PACUtils.pm");
like($appversion, qr/^\d+\.\d+\.\d+$/, "APPVERSION is semver: $appversion");

# debian/changelog first entry matches APPVERSION
{
    open my $fh, '<', 'dist/deb/debian/changelog'
        or BAIL_OUT("Cannot open debian/changelog: $!");
    my $first = <$fh>;
    close $fh;
    like($first, qr/asbru-plus/, 'changelog first entry is asbru-plus');
    like($first, qr/\Q$appversion\E/, "changelog version matches APPVERSION ($appversion)");
}

# RPM spec version entry
{
    open my $fh, '<', 'dist/rpm/asbru.spec' or BAIL_OUT("Cannot open asbru.spec: $!");
    my $content = do { local $/; <$fh> };
    close $fh;
    like($content, qr/^Name:\s+asbru-plus/m,      'RPM Name is asbru-plus');
    like($content, qr/Obsoletes:\s+asbru-cm/,      'RPM Obsoletes asbru-cm');
    unlike($content, qr/https?:\/\/asbru-cm\.net/, 'RPM URL does not point to old website');
}

# ── debian/control correctness ────────────────────────────────────────────────

{
    open my $fh, '<', 'dist/deb/debian/control' or BAIL_OUT("Cannot open debian/control: $!");
    my $content = do { local $/; <$fh> };
    close $fh;

    like($content, qr/^Source:\s+asbru-plus/m,         'Source is asbru-plus');
    like($content, qr/^Package:\s+asbru-plus/m,         'Package is asbru-plus');
    like($content, qr/Replaces:\s+asbru-cm/,            'Replaces asbru-cm');
    like($content, qr/Conflicts:\s+asbru-cm/,           'Conflicts asbru-cm');
    like($content, qr/debhelper\s*\(>=\s*10\)/,         'Build-Depends debhelper >= 10');
    like($content, qr/freerdp2-x11|freerdp3-x11/,       'Suggests freerdp2 or freerdp3');
    unlike($content, qr/freerdp-x11(?![\d])/,           'Does not depend on old freerdp-x11');
    unlike($content, qr/https?:\/\/asbru-cm\.net/,      'No reference to old website');
}

# ── debian/compat vs Build-Depends ───────────────────────────────────────────

{
    open my $fh, '<', 'dist/deb/debian/compat' or BAIL_OUT("Cannot open compat: $!");
    my $compat = <$fh>;
    close $fh;
    chomp $compat;
    is($compat, '10', 'compat file is 10');
}

# ── Required files exist ──────────────────────────────────────────────────────

my @required = qw(
    asbru-cm
    lib/PACMain.pm
    lib/PACUtils.pm
    lib/PACTerminal.pm
    lib/PACConfig.pm
    lib/asbru_conn
    lib/method/PACMethod_ssh.pm
    lib/method/PACMethod_xfreerdp.pm
    dist/deb/debian/control
    dist/deb/debian/changelog
    dist/deb/debian/install
    dist/deb/debian/asbru-plus.links
    dist/rpm/asbru.spec
    ci/build_package.sh
    .github/workflows/package-build.yml
    .github/workflows/build-snapshots.yml
    .github/workflows/build-release.yml
);

for my $f (@required) {
    ok(-f $f, "Required file exists: $f");
}

# ── Old files should not exist ────────────────────────────────────────────────

my @removed = qw(
    dist/deb/debian/asbru-cm.links
    dist/deb/debian/asbru-cm-docs.docs
    dist/deb/debian/debhelper-build-stamp
    .github/workflows/build-loki.yml
    .github/workflows/docs.yml
    .github/workflows/no-response-bot.yml
);

for my $f (@removed) {
    ok(!-f $f, "Removed file absent: $f");
}

# ── install file references existing binary ───────────────────────────────────

{
    open my $fh, '<', 'dist/deb/debian/install' or BAIL_OUT("Cannot open install: $!");
    my @lines = <$fh>;
    close $fh;
    my ($bin_line) = grep { /^asbru-cm/ } @lines;
    ok(defined $bin_line, 'install file references asbru-cm binary');
    ok(-f 'asbru-cm', 'asbru-cm binary exists in repo root');
}

done_testing();
