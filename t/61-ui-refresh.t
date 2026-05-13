#!/usr/bin/perl
# t/61-ui-refresh.t — PAC::UI::Refresh sidebar/info-pane refresh.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

# Pull Gtk3 in at compile time so Glib::Object::Introspection can wire up
# its INIT block before any test code runs. Loading via require_ok further
# down would trip "Too late to run INIT block" on stderr.
use Gtk3;

require_ok('PAC::UI::Refresh');
can_ok('PAC::UI::Refresh', $_)
    for qw(with_uuid clear_tab_labels preferences favourites history clusters
           cluster_list favourite_list);

my $src = do {
    open my $fh, '<', "$RealBin/../lib/PAC/UI/Refresh.pm" or die "open: $!";
    local $/; <$fh>;
};

# Package + entries
like($src, qr/^package PAC::UI::Refresh;/m, 'declares package');
like($src, qr/^sub with_uuid\b/m,        'has with_uuid');
like($src, qr/^sub clear_tab_labels\b/m, 'has clear_tab_labels');
like($src, qr/^sub preferences\b/m,      'has preferences');
like($src, qr/^sub favourites\b/m,       'has favourites');
like($src, qr/^sub history\b/m,          'has history');
like($src, qr/^sub clusters\b/m,         'has clusters');
like($src, qr/^sub cluster_list\b/m,     'has cluster_list');
like($src, qr/^sub favourite_list\b/m,   'has favourite_list');

# cluster_list rebuilds treeClusters from defaults + getCFGClusters
like($src, qr/\{treeClusters\}\{data\}/,
    'cluster_list writes treeClusters{data}');
like($src, qr/auto cluster/, 'cluster_list reads auto-cluster defaults');
like($src, qr/getCFGClusters/,
    'cluster_list reads cluster-manager via getCFGClusters');
like($src, qr/\$PACMain::AUTOCLUSTERICON/,
    'cluster_list reads AUTOCLUSTERICON from PACMain');
like($src, qr/\$PACMain::CLUSTERICON/,
    'cluster_list reads CLUSTERICON from PACMain');

# favourite_list rebuilds treeFavourites + chains favourites()
like($src, qr/\{treeFavourites\}\{data\}/,
    'favourite_list writes treeFavourites{data}');
like($src, qr/'favourite'/, 'favourite_list filters by favourite=1');
like($src, qr/favourites\(\$self\)/,
    'favourite_list chains a favourites() refresh');

# with_uuid welcome blurb + APP name from PACUtils
like($src, qr/__PAC__ROOT__/, 'with_uuid handles root sentinel');
like($src, qr/\$PACUtils::APPNAME/, 'reads APPNAME from PACUtils');
like($src, qr/\$PACUtils::APPVERSION/, 'reads APPVERSION from PACUtils');
like($src, qr/Welcome to/, 'with_uuid emits welcome blurb');
like($src, qr/descBuffer/, 'with_uuid sets descBuffer');
like($src, qr/frameStatistics/, 'with_uuid handles statistics frame');
like($src, qr/frameScreenshots/, 'with_uuid handles screenshots frame');

# clear_tab_labels resets all four
like($src, qr/nbTreeTabLabel.*set_text\('Connections'\)/,
    'clear resets Connections label');
like($src, qr/nbFavTabLabel.*set_text\('Favourites'\)/,
    'clear resets Favourites label');
like($src, qr/nbHistTabLabel.*set_text\('History'\)/,
    'clear resets History label');
like($src, qr/nbCluTabLabel.*set_text\('Clusters'\)/,
    'clear resets Clusters label');

# preferences sensitivity matrix
like($src, qr/treeConnections.*_getSelectedUUIDs/,
    'preferences reads selection from treeConnections');
like($src, qr/groupAddBtn.*set_sensitive/, 'preferences toggles groupAddBtn');
like($src, qr/connExecBtn/, 'preferences toggles connExecBtn');
like($src, qr/_NO_PROPAGATE_FAV_TOGGLE/,
    'preferences guards favourite-toggle propagation');
like($src, qr/lockApplicationBtn/, 'preferences updates lockApplicationBtn');
like($src, qr/_TRAY/, 'preferences toggles tray active/passive');
like($src, qr/Pango::FontDescription::from_string/,
    'preferences applies info-pane font');

# favourites: most buttons forced 0, edit/exec context-dependent
like($src, qr/treeFavourites.*_getSelectedUUIDs/,
    'favourites reads selection from treeFavourites');
like($src, qr/groupAddBtn.*set_sensitive\(0\)/,
    'favourites disables groupAddBtn');
like($src, qr/asbru-favourite-on/, 'favourites uses on icon');

# history: '__PAC_SHELL__' magic
like($src, qr/treeHistory.*_getSelectedUUIDs/,
    'history reads selection from treeHistory');
like($src, qr/__PAC_SHELL__/, 'history excludes shell pseudo-entry from edit');

# clusters: uses _getSelectedNames (cluster names not uuids)
like($src, qr/treeClusters.*_getSelectedNames/,
    'clusters reads selection from treeClusters via _getSelectedNames');
like($src, qr/with_uuid\(\$self,\s*'__PAC__ROOT__'\)/,
    'clusters resets info-pane to root welcome');

# PACMain wrappers
my $main = do {
    open my $fh, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$fh>;
};
like($main, qr/^require PAC::UI::Refresh/m,
    'PACMain requires PAC::UI::Refresh');
like($main, qr/sub _updateGUIWithUUID\s*\{\s*goto\s*&PAC::UI::Refresh::with_uuid\s*;\s*\}/,
    '_updateGUIWithUUID proxy');
like($main, qr/sub _clearLeftMenuTabLabels\s*\{\s*goto\s*&PAC::UI::Refresh::clear_tab_labels\s*;\s*\}/,
    '_clearLeftMenuTabLabels proxy');
like($main, qr/sub _updateGUIPreferences\s*\{\s*goto\s*&PAC::UI::Refresh::preferences\s*;\s*\}/,
    '_updateGUIPreferences proxy');
like($main, qr/sub _updateGUIFavourites\s*\{\s*goto\s*&PAC::UI::Refresh::favourites\s*;\s*\}/,
    '_updateGUIFavourites proxy');
like($main, qr/sub _updateGUIHistory\s*\{\s*goto\s*&PAC::UI::Refresh::history\s*;\s*\}/,
    '_updateGUIHistory proxy');
like($main, qr/sub _updateGUIClusters\s*\{\s*goto\s*&PAC::UI::Refresh::clusters\s*;\s*\}/,
    '_updateGUIClusters proxy');
like($main, qr/sub _updateClustersList\s*\{\s*goto\s*&PAC::UI::Refresh::cluster_list\s*;\s*\}/,
    '_updateClustersList proxy');
like($main, qr/sub _updateFavouritesList\s*\{\s*goto\s*&PAC::UI::Refresh::favourite_list\s*;\s*\}/,
    '_updateFavouritesList proxy');

# POD
like($src, qr/^=head1 NAME/m,            'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m,      'POD: PUBLIC API');
like($src, qr/^=item with_uuid\b/m,      'POD =item with_uuid');
like($src, qr/^=item clear_tab_labels\b/m, 'POD =item clear_tab_labels');
like($src, qr/^=item preferences\b/m,    'POD =item preferences');
like($src, qr/^=item favourites\b/m,     'POD =item favourites');
like($src, qr/^=item history\b/m,        'POD =item history');
like($src, qr/^=item clusters\b/m,       'POD =item clusters');
like($src, qr/^=item cluster_list\b/m,   'POD =item cluster_list');
like($src, qr/^=item favourite_list\b/m, 'POD =item favourite_list');

done_testing();
