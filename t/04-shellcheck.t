#!/usr/bin/perl
# t/04-shellcheck.t — ShellCheck validation for all bash scripts
use strict;
use warnings;
use Test::More;

# Check if shellcheck is available
my $shellcheck = qx{which shellcheck 2>/dev/null};
chomp $shellcheck;

unless ($shellcheck) {
    plan skip_all => 'shellcheck not installed (apt-get install shellcheck)';
}

my @scripts = (
    'ci/build_package.sh',
    'docker/build-deb/test.sh',
    'docker/build-rpm/test.sh',
    'docker/test/entrypoint.sh',
);

plan tests => scalar @scripts;

for my $script (@scripts) {
    SKIP: {
        skip "File not found: $script", 1 unless -f $script;
        my $out = qx{shellcheck --severity=error "$script" 2>&1};
        ok($? == 0, "shellcheck: $script") or diag($out);
    }
}
