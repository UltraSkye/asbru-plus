#!/usr/bin/perl
# t/64-tree-build.t — PAC::Tree::Build surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::Tree::Build');
can_ok('PAC::Tree::Build', $_) for qw(load recur_load);

my $src = do {
    open my $fh, '<', "$RealBin/../lib/PAC/Tree/Build.pm" or die "open: $!";
    local $/; <$fh>;
};

# Package + entries
like($src, qr/^package PAC::Tree::Build;/m, 'declares package');
like($src, qr/^sub load\b/m,                'has load');
like($src, qr/^sub recur_load\b/m,          'has recur_load');

# Reads PACMain icons (qualified)
like($src, qr/\$PACMain::GROUPICON_ROOT/,   'reads GROUPICON_ROOT');
like($src, qr/\$PACMain::GROUPICONCLOSED/,  'reads GROUPICONCLOSED');

# Root node has the "<b>My Connections</b>" label
like($src, qr/<b>My Connections<\/b>/, 'root label preserved');
like($src, qr/__PAC__ROOT__/, 'root UUID sentinel preserved');

# Cursor moves to root after build
like($src, qr/set_cursor\(\$tree->_getPath\('__PAC__ROOT__'\)/,
    'load() moves cursor to root');

# recur_load distinguishes group vs leaf
like($src, qr/_is_group/, 'recur_load checks _is_group');
like($src, qr/__treeBuildNodeName/,
    'recur_load uses __treeBuildNodeName for display label');

# Legacy signature preserved
like($src, qr/legacy signature.*unused/i,
    'load() documents that $group arg is legacy/unused');

# PACMain wrappers
my $main = do {
    open my $fh, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$fh>;
};
like($main, qr/^require PAC::Tree::Build/m,
    'PACMain requires PAC::Tree::Build');
like($main, qr/sub _loadTreeConfiguration\s*\{\s*goto\s*&PAC::Tree::Build::load\s*;\s*\}/,
    '_loadTreeConfiguration proxy');
like($main, qr/sub __recurLoadTree\s*\{\s*goto\s*&PAC::Tree::Build::recur_load\s*;\s*\}/,
    '__recurLoadTree proxy');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item load\b/m,      'POD =item load');
like($src, qr/^=item recur_load\b/m,'POD =item recur_load');

done_testing();
