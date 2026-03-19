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
        return if $File::Find::name =~ m{/ex/};  # local shims, not standalone
        push @files, $File::Find::name if /\.(pm|pl)$/ || $_ eq 'asbru-cm';
    },
    'lib', 'utils', 'res'
);
push @files, 'asbru-cm';

@files = sort grep { -f $_ } @files;

plan tests => scalar @files;

# Include all lib paths: lib itself, lib/method, lib/edit, lib/ex (shims)
my $inc = join(' ', map { "-I$_" } qw(lib lib/ex lib/method lib/edit utils));

for my $file (@files) {
    my $out = qx{perl -wc $inc "$file" 2>&1};
    my $exit = $?;

    if ($exit == 0 || $out =~ /syntax OK/m) {
        pass("Syntax OK: $file");
    } elsif ($out =~ /Can't locate .+?\.pm in \@INC/m
          || $out =~ /Gtk-WARNING.*cannot open display/m) {
        # Missing module or no display — dependency issue, not a code syntax error.
        # Run tests with Xvfb (DISPLAY=:99) and full deps to eliminate these.
      SKIP: { skip "Missing dependency: $file", 1 }
    } else {
        fail("Syntax OK: $file") or diag($out);
    }
}
