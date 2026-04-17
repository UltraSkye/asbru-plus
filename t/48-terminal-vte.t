#!/usr/bin/perl
# t/48-terminal-vte.t — PAC::Terminal::Vte version-tolerant feed wrappers.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::Terminal::Vte');
can_ok('PAC::Terminal::Vte', $_) for qw(feed feed_child feed_child_binary probe);

# probe() takes a $self that owns _Vte hash — verify it exists
my $src_check = do {
    open my $f, '<', "$RealBin/../lib/PAC/Terminal/Vte.pm" or die "open: $!";
    local $/; <$f>;
};
like($src_check, qr/sub probe\b/, 'probe() declared');
like($src_check, qr/_Vte}\{major_version}/, 'probe sets major_version');
like($src_check, qr/_Vte}\{vte_feed_child}/, 'probe sets vte_feed_child');
like($src_check, qr/_Vte}\{match_regex}/,    'probe sets match_regex');
like($src_check, qr/_Vte}\{get_text_range}/, 'probe sets get_text_range');

# PACMain wrapper still in place
my $main = do {
    open my $f, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$f>;
};
like($main, qr/sub _setVteCapabilities \{[^}]*PAC::Terminal::Vte::probe/s,
    'PACMain._setVteCapabilities wrapper calls probe');

my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Terminal/Vte.pm" or die "open: $!";
    local $/; <$f>;
};

# Version-dispatch checks
like($src, qr/vte_feed_child/,  'reads vte_feed_child capability flag');
like($src, qr/vte_feed_binary/, 'reads vte_feed_binary capability flag');
like($src, qr/feed_version == 1/, 'dispatches on feed_version');

# bytes pragma for length
like($src, qr/use bytes/, 'uses bytes pragma for length()');

# unpack pattern
like($src, qr/unpack\('C\*'/, 'unpacks as octet stream');

# Behavior tests with mock VTE
{
    package MockVTE;
    sub new { bless { feed_calls => [], feed_child_calls => [],
                       feed_child_binary_calls => [] }, shift }
    sub feed { my $s = shift; push @{$s->{feed_calls}}, [@_] }
    sub feed_child { my $s = shift; push @{$s->{feed_child_calls}}, [@_] }
    sub feed_child_binary { my $s = shift; push @{$s->{feed_child_binary_calls}}, [@_] }
}

# Set up the version-dispatch globals
$PACMain::FUNCS{_MAIN}{_Vte}{vte_feed_child}  = 1;  # use new API
$PACMain::FUNCS{_MAIN}{_Vte}{vte_feed_binary} = 1;

my $vte = MockVTE->new;
PAC::Terminal::Vte::feed($vte, "hello");
is(scalar @{$vte->{feed_calls}}, 1, 'feed: one call');
isa_ok($vte->{feed_calls}[0][0], 'ARRAY', 'feed: arrayref of bytes');
is_deeply($vte->{feed_calls}[0][0], [unpack 'C*', 'hello'],
    'feed: byte values match input');

PAC::Terminal::Vte::feed_child($vte, "ls\n");
is(scalar @{$vte->{feed_child_calls}}, 1, 'feed_child: one call');
isa_ok($vte->{feed_child_calls}[0][0], 'ARRAY', 'feed_child v1: arrayref');

PAC::Terminal::Vte::feed_child_binary($vte, "\xff\xfe\xfd");
is(scalar @{$vte->{feed_child_binary_calls}}, 1, 'feed_child_binary: one call');

# Old-API path (version != 1) — feed_child uses 2-arg form
$PACMain::FUNCS{_MAIN}{_Vte}{vte_feed_child} = 0;
$vte = MockVTE->new;
PAC::Terminal::Vte::feed_child($vte, "old-api");
is(scalar @{$vte->{feed_child_calls}}, 1, 'feed_child v0: one call');
is($vte->{feed_child_calls}[0][0], 'old-api',
    'feed_child v0: passes string as first arg');
is($vte->{feed_child_calls}[0][1], length('old-api'),
    'feed_child v0: passes length as second arg');

# PACUtils proxies wired
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Terminal::Vte/m,
    'PACUtils requires PAC::Terminal::Vte');
for my $pair (
    [_vteFeed             => 'feed'],
    [_vteFeedChild        => 'feed_child'],
    [_vteFeedChildBinary  => 'feed_child_binary'],
) {
    my ($legacy, $new) = @$pair;
    like($utils,
        qr/sub \Q$legacy\E\s*\{\s*goto\s*&PAC::Terminal::Vte::\Q$new\E\s*;\s*\}/,
        "$legacy is goto-proxy");
}

# POD
like($src, qr/^=head1 NAME/m,                'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m,          'POD: PUBLIC API');
for my $sub (qw(feed feed_child feed_child_binary)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item $sub");
}

done_testing();
