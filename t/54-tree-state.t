#!/usr/bin/perl
# t/54-tree-state.t — PAC::Tree::State surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $st = "$RealBin/../lib/PAC/Tree/State.pm";
ok(-r $st, 'PAC/Tree/State.pm exists');

my $src = do {
    open my $f, '<', $st or die "open: $!";
    local $/; <$f>;
};

# Package + 2 entries
like($src, qr/^package PAC::Tree::State;/m, 'declares package');
like($src, qr/^sub save\b/m, 'has save');
like($src, qr/^sub load\b/m, 'has load');

# Reads PACMain::CFG_FILE
like($src, qr/\$PACMain::CFG_FILE/, 'reads $PACMain::CFG_FILE');

# Notebook page format
like($src, qr/tree_page_/, 'uses tree_page_N format');
like($src, qr/scroll1.*scroll2.*scroll3.*vboxclu/s,
    'mentions all 4 notebook page widgets');

# Walk + restore patterns
like($src, qr/row_expanded\(\$path\)/, 'save: checks row_expanded');
like($src, qr/expand_row\(\$path/, 'load: calls expand_row');
like($src, qr/reorder_child/, 'load: re-orders notebook tabs');

# PACMain wrappers
my $main = do {
    open my $f, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$f>;
};
like($main, qr/^require PAC::Tree::State/m, 'PACMain requires PAC::Tree::State');
like($main, qr/sub _saveTreeExpanded\s*\{\s*goto\s*&PAC::Tree::State::save\s*;\s*\}/,
    '_saveTreeExpanded is goto-proxy');
like($main, qr/sub _loadTreeExpanded\s*\{\s*goto\s*&PAC::Tree::State::load\s*;\s*\}/,
    '_loadTreeExpanded is goto-proxy');

# CFG_FILE promoted to 'our' (regression gate)
like($main, qr/^our \$CFG_FILE\s*=/m, 'PACMain $CFG_FILE is "our"');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item save\b/m,      'POD =item save');
like($src, qr/^=item load\b/m,      'POD =item load');

done_testing();
