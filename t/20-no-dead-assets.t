#!/usr/bin/perl
# t/20-no-dead-assets.t
# Static linter: every theme-asset path referenced from Perl/Glade code
# must actually exist in res/themes/{default,asbru-dark}/ or res/.
# Catches the class of bug where the icon file gets renamed but a few
# call sites are missed (this happened repeatedly during the Lucide
# migration earlier in the project).
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $repo  = "$RealBin/..";
my @perl  = glob "$repo/lib/*.pm $repo/lib/*/*.pm $repo/lib/edit/*.pm";
my %refs;

for my $f (@perl, "$repo/asbru-cm") {
    next unless -r $f;
    open(my $fh, '<', $f) or next;
    while (my $line = <$fh>) {
        # $THEME_DIR / $RES_DIR / "themes/<name>/" base
        while ($line =~ m{["'](?:\$\w+/)?((?:asbru[-_]|gtk-)[\w\-]+\.(?:png|svg|jpg))["']}g) {
            push @{ $refs{$1} }, "$f:$.";
        }
    }
    close $fh;
}

# Resolve in either default/ or asbru-dark/ or RES root
my @missing;
for my $name (sort keys %refs) {
    my @candidates = (
        "$repo/res/themes/default/$name",
        "$repo/res/themes/asbru-dark/$name",
        "$repo/res/$name",
    );
    my $found = grep { -f $_ } @candidates;
    next if $found;
    push @missing, [$name, $refs{$name}];
}

if (@missing) {
    diag("Dead asset references found:");
    for my $m (@missing) {
        diag("  $m->[0] referenced at " . join(", ", @{ $m->[1] }));
    }
}
ok(scalar(@missing) == 0, "no dead asset references in Perl code");

# Same check against Glade XML
my $glade = "$repo/res/asbru.glade";
if (-r $glade) {
    open(my $gfh, '<', $glade) or die "open $glade: $!";
    local $/;
    my $g = <$gfh>;
    close $gfh;
    my @glade_refs;
    while ($g =~ m{<property name="pixbuf">([^<]+)</property>}g) {
        push @glade_refs, $1;
    }
    my @glade_missing;
    for my $name (@glade_refs) {
        my @candidates = (
            "$repo/res/themes/default/$name",
            "$repo/res/themes/asbru-dark/$name",
            "$repo/res/$name",
        );
        push @glade_missing, $name unless grep { -f $_ } @candidates;
    }
    if (@glade_missing) {
        diag("Glade pixbuf entries missing on disk: @glade_missing");
    }
    ok(scalar(@glade_missing) == 0, "all Glade <pixbuf> references resolve");
} else {
    pass("(skipped) glade not present");
}

done_testing();
