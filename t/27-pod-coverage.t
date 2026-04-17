#!/usr/bin/perl
# t/27-pod-coverage.t — Every public sub in lib/PAC/* and lib/PACSshConfig.pm
# must be documented in POD.
#
# Policy:
#   - Modules under lib/PAC/* and lib/PACSshConfig.pm are NEW code: every
#     non-underscore sub MUST appear in POD (=item, =head, or =head[12-4]).
#   - Legacy modules (PACMain.pm, PACUtils.pm, PACTerminal.pm, etc.) are
#     grandfathered — POD coverage there is a separate effort.
#
# Implementation note:
#   We don't depend on Test::Pod::Coverage / Pod::Coverage at runtime to
#   keep the test runnable on bare Perl. Instead we do a regex-level scan:
#   parse subs from the source, parse =item / =head names from POD, and
#   compare. This catches the same bugs (undocumented public APIs) without
#   the heavyweight dep.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

# Recursively walk lib/PAC/ so nested modules (PAC::Config::Schema, etc.)
# are gated, not just top-level ones.
my @files;
_walk("$RealBin/../lib/PAC", \@files);
push @files, "$RealBin/../lib/PACSshConfig.pm";

sub _walk {
    my ($dir, $out) = @_;
    return unless -d $dir;
    opendir(my $dh, $dir) or return;
    while (my $entry = readdir $dh) {
        next if $entry =~ /^\.+$/;
        my $path = "$dir/$entry";
        if (-d $path) { _walk($path, $out); }
        elsif ($path =~ /\.pm\z/) { push @$out, $path; }
    }
    closedir $dh;
}

unless (@files) {
    plan skip_all => 'no PAC::* modules to check';
}

for my $file (@files) {
    next unless -f $file;
    check_file($file);
}

done_testing();

#-------------------------------------------------------------------------
sub check_file {
    my $file = shift;

    open(my $fh, '<', $file) or do {
        fail("cannot open $file: $!");
        return;
    };
    local $/;
    my $src = <$fh>;
    close $fh;

    # Split into code half and POD half. POD directives MUST be at line
    # start (^=word). Without this anchor, the regex would match strings
    # like '# for type=enum' inside comments. Prefer __END__ as the split
    # point when present (cleanest); otherwise fall back to the first
    # ^=word line.
    my ($code, $pod);
    if ($src =~ /^(.*?)__END__\s*\n(.*)\z/ms) {
        $code = $1;
        $pod  = $2;
    } elsif ($src =~ /^(.*?)(?=^=\w)/ms) {
        $code = $1;
        $pod  = substr($src, length $1);
    } else {
        $code = $src;
        $pod  = '';
    }

    # Public subs = sub <Name> { … } where Name does NOT start with `_`.
    my @public_subs;
    while ($code =~ /^\s*sub\s+([A-Za-z][A-Za-z0-9_]*)\s*[\{\(]/gm) {
        my $name = $1;
        next if $name =~ /^_/;             # internal
        next if $name =~ /^(BEGIN|END|DESTROY|AUTOLOAD|import|new)$/;
        push @public_subs, $name;
    }

    if (!@public_subs) {
        pass("$file: no public subs to document");
        return;
    }

    # POD names: anything mentioned in =item or =head
    my %documented;
    while ($pod =~ /^=(?:item|head[1-4])\s+([A-Za-z][A-Za-z0-9_]*)/gm) {
        $documented{$1} = 1;
    }
    # Also accept names mentioned in C<…> tags within the POD body.
    while ($pod =~ /C<([A-Za-z][A-Za-z0-9_]+)>/g) {
        $documented{$1} = 1;
    }

    my @undocumented = grep { !$documented{$_} } @public_subs;

    is(scalar @undocumented, 0,
        "$file: all " . scalar(@public_subs) . " public sub(s) documented")
      or diag("undocumented in $file: @undocumented");
}
