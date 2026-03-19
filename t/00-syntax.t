#!/usr/bin/perl
# t/00-syntax.t — Perl syntax check for all modules and scripts
use strict;
use warnings;
use Test::More;
use File::Find;

my @files;
find(
    sub {
        return if $File::Find::name =~ m{/\.git/};
        push @files, $File::Find::name if /\.(pm|pl)$/ || $_ eq 'asbru-cm';
    },
    'lib', 'utils', 'res'
);
push @files, 'asbru-cm';

@files = sort grep { -f $_ } @files;

plan tests => scalar @files;

for my $file (@files) {
    my $out = qx{perl -wc "$file" 2>&1};
    my $ok  = ($? == 0);
    ok($ok, "Syntax OK: $file") or diag($out);
}
