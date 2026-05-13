#!/usr/bin/perl
# t/46-tree-sort-and-clipboard.t — PAC::Tree::Sort + PAC::Clipboard
# extraction surface checks plus behavior verification of compare_pair.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

# Pull Gtk3 in at compile time so Glib::Object::Introspection wires up
# its INIT block before any test code runs (avoids "Too late to run INIT
# block" stderr noise from require_ok of a Gtk3-using module).
use Gtk3;

# ── PAC::Tree::Sort ─────────────────────────────────────────────────
require_ok('PAC::Tree::Sort');
can_ok('PAC::Tree::Sort', $_) for qw(compare_pair compare);

# Build a fake $PACMain::FUNCS{_MAIN}{_CFG} for the comparator
{
    no warnings 'once';
    $PACMain::FUNCS{_MAIN}{_CFG} = {
        defaults => { 'sort groups first' => 1 },
        environments => {
            'g1' => { _is_group => 1 },
            'g2' => { _is_group => 1 },
            'n1' => { _is_group => 0 },
            'n2' => { _is_group => 0 },
        },
    };
}

my $group_a = { value => [undef, 'Alpha Group', 'g1'] };
my $group_z = { value => [undef, 'Zeta Group',  'g2'] };
my $node_a  = { value => [undef, 'Alpha Node',  'n1'] };
my $node_b  = { value => [undef, 'Beta Node',   'n2'] };

# 1. compare_pair (explicit-args form)
is(PAC::Tree::Sort::compare_pair($group_a, $node_b), -1, 'group before node');
is(PAC::Tree::Sort::compare_pair($node_b, $group_a),  1, 'node after group');
is(PAC::Tree::Sort::compare_pair($group_a, $group_z), -1, 'alpha < zeta group');
is(PAC::Tree::Sort::compare_pair($node_a, $node_b),  -1, 'alpha < beta node');

# 2. Used in real sort context — this is the regression I was hunting:
#    sort with a SUBNAME from across packages does NOT propagate $a/$b.
#    Using a sort block + compare_pair is the correct pattern.
my @nodes = ($node_b, $group_a, $node_a, $group_z);
my @sorted = sort { PAC::Tree::Sort::compare_pair($a, $b) } @nodes;
is($sorted[0]{value}[1], 'Alpha Group', 'sort: groups first');
is($sorted[1]{value}[1], 'Zeta Group',  'sort: alpha then zeta group');
is($sorted[2]{value}[1], 'Alpha Node',  'sort: nodes after groups, alphabetical');
is($sorted[3]{value}[1], 'Beta Node',   'sort: beta node last');

# 3. Without groups-first: pure alphabetical
$PACMain::FUNCS{_MAIN}{_CFG}{defaults}{'sort groups first'} = 0;
@sorted = sort { PAC::Tree::Sort::compare_pair($a, $b) } @nodes;
is($sorted[0]{value}[1], 'Alpha Group', 'no-groups-first: alpha first');
is($sorted[3]{value}[1], 'Zeta Group',  'no-groups-first: zeta last');

# 4. HTML stripped before compare
my $with_html = { value => [undef, '<b>Beta</b>',   'n2'] };
my $plain     = { value => [undef, 'Alpha',         'n1'] };
$PACMain::FUNCS{_MAIN}{_CFG}{defaults}{'sort groups first'} = 0;
is(PAC::Tree::Sort::compare_pair($with_html, $plain), 1,
    'HTML stripped: Beta > Alpha');

# 5. Source: must have BOTH compare_pair (new, safe) AND compare
#    (legacy, package-globals).
my $sort_src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Tree/Sort.pm" or die "open: $!";
    local $/; <$f>;
};
like($sort_src, qr/^sub compare_pair\b/m, 'has compare_pair');
like($sort_src, qr/^sub compare\b/m, 'has compare (legacy package-globals form)');

# ── PAC::Clipboard ──────────────────────────────────────────────────
require_ok('PAC::Clipboard');
can_ok('PAC::Clipboard', 'copy_password');

my $clip_src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Clipboard.pm" or die "open: $!";
    local $/; <$f>;
};

# Security gates preserved
like($clip_src, qr/Glib::Timeout->add_seconds.*15/s,
    'PAC::Clipboard: 15-second auto-clear');
like($clip_src, qr/\\0.*x length/, 'PAC::Clipboard: zero-out on clear');
like($clip_src, qr/PRIMARY/, 'uses PRIMARY clipboard');
like($clip_src, qr/isKeePassMask/, 'resolves KeePass masks before copy');

# ── PACUtils proxies wired ──────────────────────────────────────────
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Tree::Sort/m, 'PACUtils requires PAC::Tree::Sort');
like($utils, qr/^require PAC::Clipboard/m,  'PACUtils requires PAC::Clipboard');
like($utils, qr/PAC::Tree::Sort::compare_pair/,
    'PACUtils._sortTreeData uses compare_pair (correct cross-package pattern)');
like($utils, qr/sub _copyPass\s*\{\s*goto\s*&PAC::Clipboard::copy_password\s*;\s*\}/,
    '_copyPass is goto-proxy');

# ── POD ─────────────────────────────────────────────────────────────
like($sort_src, qr/^=head1 NAME/m,        'Sort POD: NAME');
like($sort_src, qr/^=item compare_pair\b/m,'Sort POD =item compare_pair');
like($sort_src, qr/^=item compare\b/m,    'Sort POD =item compare');

like($clip_src, qr/^=head1 NAME/m,        'Clipboard POD: NAME');
like($clip_src, qr/^=item copy_password\b/m,'Clipboard POD =item copy_password');

done_testing();
