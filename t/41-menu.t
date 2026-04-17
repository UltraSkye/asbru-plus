#!/usr/bin/perl
# t/41-menu.t — Surface check for PAC::Menu extraction.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $menu_pm = "$RealBin/../lib/PAC/Menu.pm";
ok(-r $menu_pm, 'lib/PAC/Menu.pm exists');

my $src = do {
    open my $f, '<', $menu_pm or die "open: $!";
    local $/; <$f>;
};

# 1. Package + three public subs
like($src, qr/^package PAC::Menu;/m, 'declares package');
like($src, qr/^sub favourite_connections\b/m, 'has favourite_connections');
like($src, qr/^sub cluster_connections\b/m,   'has cluster_connections');
like($src, qr/^sub available_connections\b/m, 'has available_connections');

# 2. Recursion fixed (was _menuAvailableConnections, now available_connections)
unlike($src, qr/_menuAvailableConnections\(/,
    'recursive call uses new name (no leftover _menuAvailableConnections)');
like($src, qr/submenu\s*=>\s*available_connections\(/,
    'recursive call to available_connections present');

# 3. Cross-module references properly qualified
# After the P3/17 sort fix, the comparator is PAC::Tree::Sort::compare_pair
# (via a sort block) — see commit comment for why the legacy SUBNAME form
# was unsafe across packages.
like($src, qr/PAC::Tree::Sort::compare_pair/,
    'sort uses PAC::Tree::Sort::compare_pair (post-P3/17 sort fix)');
like($src, qr/PACUtils::__\(/, '__() qualified to PACUtils::');
like($src, qr/PACMain::FUNCS/, 'PACMain::FUNCS qualified (already was)');
like($src, qr/PACMain::UNITY/, 'PACMain::UNITY qualified (already was)');

# 4. PACUtils proxy in place
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/sub _menuFavouriteConnections\s*\{\s*goto\s*&PAC::Menu::favourite_connections\s*;\s*\}/,
    '_menuFavouriteConnections proxy wired');
like($utils, qr/sub _menuClusterConnections\s*\{\s*goto\s*&PAC::Menu::cluster_connections\s*;\s*\}/,
    '_menuClusterConnections proxy wired');
like($utils, qr/sub _menuAvailableConnections\s*\{\s*goto\s*&PAC::Menu::available_connections\s*;\s*\}/,
    '_menuAvailableConnections proxy wired');

# 5. POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
for my $sub (qw(favourite_connections cluster_connections available_connections)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item $sub");
}

done_testing();
