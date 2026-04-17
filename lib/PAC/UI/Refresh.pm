package PAC::UI::Refresh;

###############################################################################
# PAC::UI::Refresh — refresh sidebar tab state + main info panel in
# response to a selection change on one of the four left-hand tabs
# (Connections / Favourites / History / Clusters).
#
# Each *_<tab>($self)* function:
#   1. resets all four tab labels (clear_tab_labels)
#   2. re-applies the active tab's title (if "show tree titles" is on)
#   3. updates toolbar button sensitivity for the selection
#   4. delegates to with_uuid($self, $uuid) for the right-side info pane
#      (description text + statistics + screenshots)
#
# Mechanical extraction from PACMain::_updateGUIWithUUID +
# _clearLeftMenuTabLabels + _updateGUIPreferences + _updateGUIFavourites
# + _updateGUIHistory + _updateGUIClusters. PACMain retains 1-line
# proxies; external callsites in PACConfig / PACEdit / PACTerminal
# continue to work via those proxies.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;

our $VERSION = '0.1.0';

# Translation marker — PACUtils provides __() globally; we re-import
# it as a no-op-safe fallback for headless tests where Locale::gettext
# may not be loaded.
sub __ { goto &PACUtils::__ if defined &PACUtils::__; return $_[0]; }

# with_uuid($self, $uuid) — refresh the right-side info pane to
# describe $uuid: description text, statistics frame, screenshots
# frame. Special-cases the synthetic '__PAC__ROOT__' UUID with a
# welcome blurb.
sub with_uuid {
    my $self = shift;
    my $uuid = shift;

    my $is_root = $uuid eq '__PAC__ROOT__';
    my $name    = $PACUtils::APPNAME;
    my $version = $PACUtils::APPVERSION;

    if ($is_root) {
        $$self{_GUI}{descBuffer}->set_text(qq"
Welcome to $name $version

Get started by creating your first connection group:

  1.  Click 'My Connections' in the tree on the left
  2.  Click the folder-plus icon at the top of the sidebar to add a group
  3.  Inside a group, click the file-plus icon to add a connection

Tip: right-click any tree item for more actions.

For news and updates, visit the project page on GitHub.
");
    } else {
        if (!$$self{_CFG}{'environments'}{$uuid}{'description'}) {
            $$self{_CFG}{'environments'}{$uuid}{'description'}
                = 'Insert your comments for this connection here ...';
        }
        $$self{_GUI}{descBuffer}->set_text(
            "$$self{_CFG}{'environments'}{$uuid}{'description'}"
        );
    }

    if ($$self{_CFG}{'defaults'}{'show statistics'}) {
        $$self{_GUI}{statistics}->update($uuid, $$self{_CFG});
        $$self{_GUI}{frameStatistics}->show();
    } else {
        $$self{_GUI}{frameStatistics}->hide();
    }

    if ($$self{_CFG}{'defaults'}{'show screenshots'}) {
        $$self{_GUI}{screenshots}->update(
            $$self{_CFG}{'environments'}{$uuid}, $uuid,
        );
        $$self{_GUI}{frameScreenshots}->show_all();
    } else {
        $$self{_GUI}{frameScreenshots}->hide();
    }

    return 1;
}

# clear_tab_labels($self) — reset all four sidebar notebook tab
# labels to their plain (no-icon-prefix) text. Each per-tab refresh
# function calls this then re-applies the active tab's prefixed
# title if "show tree titles" is enabled.
sub clear_tab_labels {
    my $self = shift;

    # Keep all tab labels populated at all times so every tab is
    # self-describing (the original code emptied them on each switch).
    $$self{_GUI}{nbTreeTabLabel}->set_text('Connections');
    $$self{_GUI}{nbFavTabLabel}->set_text('Favourites');
    $$self{_GUI}{nbHistTabLabel}->set_text('History');
    $$self{_GUI}{nbCluTabLabel}->set_text('Clusters');
}

# preferences($self) — refresh the Connections tab. Toolbar button
# sensitivity depends on selection size, root/group/protected flags.
# Also applies a few global preferences (tab position, tree lines,
# overlay scrolling, info-pane font, tray active/passive,
# lock-application sensitivity).
sub preferences {
    my $self = shift;

    my @sel_uuids = $$self{_GUI}{treeConnections}->_getSelectedUUIDs();
    my $total = scalar(@sel_uuids);

    my $is_group  = 0;
    my $is_root   = 0;
    my $protected = 0;
    my $uuid = $sel_uuids[0];
    defined $uuid or return 1;

    foreach my $u (@sel_uuids) {
        $u eq '__PAC__ROOT__' and $is_root = 1;
        $$self{_CFG}{'environments'}{$u}{'_is_group'}  and $is_group  = 1;
        $$self{_CFG}{'environments'}{$u}{'_protected'} and $protected = 1;
    }

    clear_tab_labels($self);
    if ($$self{_CFG}{defaults}{'show tree titles'}) {
        $$self{_GUI}{nbTreeTabLabel}->set_text(' Connections');
    }
    $$self{_GUI}{connSearch}->set_sensitive(1);
    $$self{_GUI}{groupAddBtn}->set_sensitive($total == 1 && ($is_group || $is_root) && !$protected);
    $$self{_GUI}{connAddBtn}->set_sensitive($total == 1 && ($is_group || $is_root) && !$protected);
    $$self{_GUI}{connEditBtn}->set_sensitive($total >= 1 && !$is_root);
    $$self{_GUI}{nodeRenBtn}->set_sensitive($total == 1 && !$is_root && !$protected);
    $$self{_GUI}{nodeDelBtn}->set_sensitive($total >= 1 && !$is_root && !$protected);
    $$self{_GUI}{connExecBtn}->set_sensitive($total >= 1);
    $$self{_GUI}{descView}->set_sensitive($total == 1 && !$is_root);
    $$self{_GUI}{frameStatistics}->set_sensitive($total == 1);
    $$self{_GUI}{frameScreenshots}->set_sensitive($total == 1 && !$is_root);
    $$self{_GUI}{connFavourite}->set_sensitive($total >= 1 && !($is_root || $is_group));
    $$self{_NO_PROPAGATE_FAV_TOGGLE} = 1;
    $$self{_GUI}{connFavourite}->set_active($total == 1 && !($is_root || $is_group) && $$self{_CFG}{'environments'}{$uuid}{'favourite'});
    $$self{_GUI}{connFavourite}->set_image(
        Gtk3::Image->new_from_stock(
            'asbru-favourite-' . ($$self{_CFG}{'environments'}{$uuid}{'favourite'} ? 'on' : 'off'),
            'button',
        )
    );
    $$self{_NO_PROPAGATE_FAV_TOGGLE} = 0;

    $$self{_GUI}{nb}->set_tab_pos($$self{_CFG}{'defaults'}{'tabs position'});
    $$self{_GUI}{treeConnections}->set_enable_tree_lines($$self{_CFG}{'defaults'}{'enable tree lines'});
    $$self{_GUI}{scroll1}->set_overlay_scrolling($$self{_CFG}{'defaults'}{'tree overlay scrolling'});
    $$self{_GUI}{descView}->modify_font(
        Pango::FontDescription::from_string($$self{_CFG}{'defaults'}{'info font'})
    );

    !$$self{_GUI}{main}->get_visible() || $$self{_CFG}{defaults}{'show tray icon'}
        ? $$self{_TRAY}->set_active()
        : $$self{_TRAY}->set_passive();

    $$self{_GUI}{lockApplicationBtn}->set_sensitive($$self{_CFG}{'defaults'}{'use gui password'});

    with_uuid($self, $sel_uuids[0]) if $total == 1;

    return 1;
}

# favourites($self) — refresh the Favourites tab. Most toolbar
# buttons are forced insensitive; only edit/exec/favourite remain
# context-dependent.
sub favourites {
    my $self = shift;

    my @sel_uuids = $$self{_GUI}{treeFavourites}->_getSelectedUUIDs();
    my $total = scalar(@sel_uuids);
    my $uuid  = $sel_uuids[0];

    clear_tab_labels($self);
    if ($$self{_CFG}{defaults}{'show tree titles'}) {
        $$self{_GUI}{nbFavTabLabel}->set_text(' Favourites');
    }

    $$self{_GUI}{connSearch}->set_sensitive(0);
    $$self{_GUI}{groupAddBtn}->set_sensitive(0);
    $$self{_GUI}{connAddBtn}->set_sensitive(0);
    $$self{_GUI}{connEditBtn}->set_sensitive($total >= 1 && $uuid ne '__PAC__ROOT__');
    $$self{_GUI}{nodeRenBtn}->set_sensitive(0);
    $$self{_GUI}{nodeDelBtn}->set_sensitive(0);
    $$self{_GUI}{connExecBtn}->set_sensitive($total >= 1 && $uuid ne '__PAC__ROOT__');
    $$self{_GUI}{descView}->set_sensitive(0);
    $$self{_GUI}{frameStatistics}->set_sensitive(0);
    $$self{_GUI}{frameScreenshots}->set_sensitive(0);
    $$self{_GUI}{connFavourite}->set_sensitive(1 && $uuid ne '__PAC__ROOT__');
    $$self{_NO_PROPAGATE_FAV_TOGGLE} = 1;
    $$self{_GUI}{connFavourite}->set_active($uuid ne '__PAC__ROOT__');
    $$self{_GUI}{connFavourite}->set_image(
        Gtk3::Image->new_from_stock('asbru-favourite-on', 'button')
    );
    $$self{_NO_PROPAGATE_FAV_TOGGLE} = 0;

    if ($total == 1) {
        with_uuid($self, $sel_uuids[0]);
    }

    return 1;
}

# history($self) — refresh the History tab. Edit/exec are
# context-sensitive; the magic '__PAC_SHELL__' UUID is excluded
# from edit (it's the local-shell pseudo-history entry).
sub history {
    my $self = shift;

    my @sel_uuids = $$self{_GUI}{treeHistory}->_getSelectedUUIDs();
    my $total = scalar(@sel_uuids);
    my $uuid  = $sel_uuids[0];

    clear_tab_labels($self);
    if ($$self{_CFG}{defaults}{'show tree titles'}) {
        $$self{_GUI}{nbHistTabLabel}->set_text(' History');
    }
    $$self{_GUI}{connSearch}->set_sensitive(0);
    $$self{_GUI}{groupAddBtn}->set_sensitive(0);
    $$self{_GUI}{connAddBtn}->set_sensitive(0);
    $$self{_GUI}{connEditBtn}->set_sensitive($total >= 1 && $uuid ne '__PAC__ROOT__' && $uuid ne '__PAC_SHELL__');
    $$self{_GUI}{nodeRenBtn}->set_sensitive(0);
    $$self{_GUI}{nodeDelBtn}->set_sensitive(0);
    $$self{_GUI}{connExecBtn}->set_sensitive($total >= 1 && $uuid ne '__PAC__ROOT__');
    $$self{_GUI}{descView}->set_sensitive(0);
    $$self{_GUI}{frameStatistics}->set_sensitive(0);
    $$self{_GUI}{frameScreenshots}->set_sensitive(0);
    $$self{_GUI}{connFavourite}->set_sensitive(0);
    $$self{_NO_PROPAGATE_FAV_TOGGLE} = 1;
    $$self{_GUI}{connFavourite}->set_active($$self{_CFG}{'environments'}{$uuid}{'favourite'});
    $$self{_GUI}{connFavourite}->set_image(
        Gtk3::Image->new_from_stock(
            'asbru-favourite-' . ($$self{_CFG}{'environments'}{$uuid}{'favourite'} ? 'on' : 'off'),
            'button',
        )
    );
    $$self{_NO_PROPAGATE_FAV_TOGGLE} = 0;

    with_uuid($self, $sel_uuids[0]) if $total == 1;

    return 1;
}

# clusters($self) — refresh the Clusters tab. Only exec is
# context-sensitive; the right-side info pane is reset to the
# root welcome blurb.
sub clusters {
    my $self = shift;

    my @sel_uuids = $$self{_GUI}{treeClusters}->_getSelectedNames();
    my $total = scalar(@sel_uuids);
    my $uuid  = $sel_uuids[0];

    clear_tab_labels($self);
    if ($$self{_CFG}{defaults}{'show tree titles'}) {
        $$self{_GUI}{nbCluTabLabel}->set_text(' Clusters');
    }
    $$self{_GUI}{connSearch}->set_sensitive(0);
    $$self{_GUI}{groupAddBtn}->set_sensitive(0);
    $$self{_GUI}{connAddBtn}->set_sensitive(0);
    $$self{_GUI}{connEditBtn}->set_sensitive(0);
    $$self{_GUI}{nodeRenBtn}->set_sensitive(0);
    $$self{_GUI}{nodeDelBtn}->set_sensitive(0);
    $$self{_GUI}{connExecBtn}->set_sensitive($total == 1);
    $$self{_GUI}{descView}->set_sensitive(0);
    $$self{_GUI}{frameStatistics}->set_sensitive(0);
    $$self{_GUI}{frameScreenshots}->set_sensitive(0);
    $$self{_GUI}{connFavourite}->set_sensitive(0);
    $$self{_NO_PROPAGATE_FAV_TOGGLE} = 1;
    $$self{_GUI}{connFavourite}->set_active(0);
    $$self{_NO_PROPAGATE_FAV_TOGGLE} = 0;

    with_uuid($self, '__PAC__ROOT__');

    return 1;
}

# cluster_list($self) — rebuild the Clusters sidebar tree's data
# array from $CFG{defaults}{auto cluster} plus the cluster-manager's
# saved clusters. Sorts each group alphabetically.
sub cluster_list {
    my $self = shift;

    @{ $$self{_GUI}{treeClusters}{data} } = ();

    foreach my $ac (sort { $a cmp $b }
        keys %{ $$self{_CFG}{defaults}{'auto cluster'} })
    {
        push @{ $$self{_GUI}{treeClusters}{data} },
            ({ value => [ $PACMain::AUTOCLUSTERICON, $ac ] });
    }

    foreach my $cluster (sort { $a cmp $b }
        keys %{ $$self{_CLUSTER}->getCFGClusters() })
    {
        push @{ $$self{_GUI}{treeClusters}{data} },
            ({ value => [ $PACMain::CLUSTERICON, $cluster ] });
    }

    return 1;
}

# favourite_list($self) — rebuild the Favourites sidebar tree's data
# array from environments where favourite=1, prefixing the parent
# group name when present. Then triggers a favourites() refresh.
sub favourite_list {
    my $self = shift;
    my $name;

    @{ $$self{_GUI}{treeFavourites}{data} } = ();

    foreach my $uuid (keys %{ $$self{_CFG}{'environments'} }) {
        if (!$$self{_CFG}{'environments'}{$uuid}{'favourite'}) {
            next;
        }
        my $icon  = $$self{_METHODS}{ $$self{_CFG}{'environments'}{$uuid}{'method'} }{'icon'};
        my $group = $$self{_CFG}{'environments'}{$uuid}{'parent'};
        if ($group) {
            $name  = __($$self{_CFG}{'environments'}{$uuid}{'name'});
            $group = __("$$self{_CFG}{'environments'}{$group}{'name'} : ");
            $name  = "$group$name";
        } else {
            $name = __($$self{_CFG}{'environments'}{$uuid}{'name'});
        }
        push @{ $$self{_GUI}{treeFavourites}{data} },
            ({ value => [ $icon, $name, $uuid ] });
    }

    favourites($self);

    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::UI::Refresh — refresh sidebar tab state + main info panel

=head1 SYNOPSIS

    use PAC::UI::Refresh;

    PAC::UI::Refresh::preferences($self);    # Connections tab
    PAC::UI::Refresh::favourites($self);     # Favourites tab
    PAC::UI::Refresh::history($self);        # History tab
    PAC::UI::Refresh::clusters($self);       # Clusters tab
    PAC::UI::Refresh::with_uuid($self, $uuid);

=head1 DESCRIPTION

Each per-tab function (C<preferences>, C<favourites>, C<history>,
C<clusters>) reads the current selection from the matching sidebar
tree, resets the four notebook tab labels (C<clear_tab_labels>),
re-applies the active tab's title when C<show tree titles> is on,
sets toolbar button sensitivity, and (for single-selection cases)
delegates to C<with_uuid> to refresh the right-side info pane.

C<with_uuid> populates the description text + statistics frame +
screenshots frame for a given UUID, with a special welcome blurb
for the synthetic C<__PAC__ROOT__> UUID.

Mechanical extraction from C<PACMain::_updateGUIWithUUID> +
C<_clearLeftMenuTabLabels> + C<_updateGUIPreferences> +
C<_updateGUIFavourites> + C<_updateGUIHistory> +
C<_updateGUIClusters>. PACMain retains 1-line proxies; external
callsites in PACConfig / PACEdit / PACTerminal continue to work.

=head1 PUBLIC API

=over

=item with_uuid($self, $uuid)

Refresh the right-side info pane for C<$uuid>. Welcomes the user
when C<$uuid> is C<'__PAC__ROOT__'>; otherwise sets the description
text and shows/hides the statistics/screenshots frames.

=item clear_tab_labels($self)

Reset the four sidebar notebook tab labels to their plain text.

=item preferences($self)

Refresh the Connections tab + global preference-driven UI bits
(tab position, tree lines, overlay scroll, info-pane font, tray,
lock-application sensitivity).

=item favourites($self)

Refresh the Favourites tab.

=item history($self)

Refresh the History tab.

=item clusters($self)

Refresh the Clusters tab.

=item cluster_list($self)

Rebuild the Clusters sidebar tree's data model from
C<$CFG{defaults}{auto cluster}> plus the cluster-manager's saved
clusters. Each group is sorted alphabetically.

=item favourite_list($self)

Rebuild the Favourites sidebar tree's data model from environments
where C<favourite=1>, prefixing the parent group name when present,
then triggers a C<favourites()> refresh.

=back

=head1 SEE ALSO

L<PAC::Window::ConnectionsList>, L<PAC::Terminal::Focus>.

=cut
