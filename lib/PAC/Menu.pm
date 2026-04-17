package PAC::Menu;

###############################################################################
# PAC::Menu — menu-spec builders for tray, sidebar, and chain-with menus.
#
# Each helper returns an arrayref of hashref menu specs that the caller
# (PACMain or PACTerminal) feeds into _wPopUpMenu / Gtk3::Menu builders.
#
# Mechanical extraction from PACUtils. PACUtils retains 1-line proxies
# for the existing callsites in PACMain, PACEdit, PACTerminal, etc.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

#-------------------------------------------------------------------------
# Public API
#-------------------------------------------------------------------------

# favourite_connections($terminal?) — favourites from cfg, sorted by name.
sub favourite_connections {
    my $terminal = shift // 0;

    my $cfg = $PACMain::FUNCS{_MAIN}{_CFG};
    my @fav;

    foreach my $uuid (keys %{$$cfg{environments}}) {
        if ($uuid eq '__PAC__ROOT__') {
            next;
        }
        if (!$$cfg{'environments'}{$uuid}{'favourite'}) {
            next;
        }

        my $group = $$cfg{'environments'}{$uuid}{'parent'} ? "$$cfg{'environments'}{$$cfg{'environments'}{$uuid}{'parent'}}{'name'} : " : '';
        my $name = "$group$$cfg{'environments'}{$uuid}{'name'}";

        if ($terminal) {
            push(@fav, {
                label => $name,
                stockicon => $PACMain::UNITY ? '' : "asbru-method-$$cfg{'environments'}{$uuid}{'method'}",
                tooltip => $$cfg{'environments'}{$uuid}{'description'},
                submenu => [
                    {label => 'Start',
                        stockicon => $PACMain::UNITY ? '' : 'gtk-media-play',
                        code => sub {
                            $PACMain::FUNCS{_MAIN}->_launchTerminals([[$uuid]]);
                        }
                    }, {
                        label => "Chain with '$$terminal{_NAME}'",
                        stockicon => $PACMain::UNITY ? '' : 'asbru-chain',
                        sensitive => $$terminal{CONNECTED},
                        code => sub {
                            $terminal->_wSelectChain($uuid);
                        }
                    }
                ]
            });
        } else {
            push(@fav, {
                label => $name,
                stockicon => $PACMain::UNITY ? '' : "asbru-method-$$cfg{'environments'}{$uuid}{'method'}",
                tooltip => $$cfg{'environments'}{$uuid}{'description'},
                code => sub {
                    $PACMain::FUNCS{_MAIN}->_launchTerminals([[$uuid]]);
                }
            });
        }
    }

    @fav = sort {lc($$a{label}) cmp lc($$b{label})} @fav;
    return \@fav;
}

sub cluster_connections {
    my @fav;

    foreach my $ac (sort {lc($a) cmp lc($b)} keys %{$PACMain::FUNCS{_MAIN}{_CFG}{defaults}{'auto cluster'}}) {
        push(@fav, {
            label => $ac,
            stockicon => $PACMain::UNITY ? '' : 'asbru-cluster-auto',
            code => sub {$PACMain::FUNCS{_MAIN}->_startCluster($ac);}
        });
    }

    foreach my $cluster (sort {lc($a) cmp lc($b)} keys %{$PACMain::FUNCS{_MAIN}{_CLUSTER}->getCFGClusters}) {
        push(@fav, {
            label => $cluster,
            stockicon => $PACMain::UNITY ? '' : 'asbru-cluster-manager2',
            code => sub {$PACMain::FUNCS{_MAIN}->_startCluster($cluster);}
        });
    }

    return \@fav;
}

sub available_connections {
    my $tree = shift // $PACMain::FUNCS{_MAIN}{_GUI}{treeConnections}{data};
    my $terminal = shift // 0;

    my $cfg = $PACMain::FUNCS{_MAIN}{_CFG};
    my @tray_menu_items;

    foreach my $elem_hash (sort PACUtils::_sortTreeData @{$tree}) {
        my $this_icon = $$elem_hash{'value'}[0];
        my $this_name = $$elem_hash{'value'}[1];
        my $this_uuid = $$elem_hash{'value'}[2];

        if ($this_uuid eq '__PAC__ROOT__') {
            next;
        }

        $this_name =~ s/<.+>(.+?)<\/.+>/$1/go;
        $this_name = PACUtils::__($this_name);

        if (scalar(@{$$elem_hash{'children'}})) {
            push(@tray_menu_items, {
                label => $this_name,
                stockicon => $PACMain::UNITY ? '' : 'asbru-group-closed',
                tooltip => $$cfg{'environments'}{$this_uuid}{'description'} // '',
                submenu => available_connections($$elem_hash{'children'}, $terminal)
            });
        } elsif ($terminal) {
            push(@tray_menu_items, {
                label => $this_name,
                stockicon => $PACMain::UNITY ? '' : "asbru-method-$$cfg{'environments'}{$this_uuid}{'method'}",
                tooltip => $$cfg{'environments'}{$this_uuid}{'description'},
                submenu => [{
                        label => 'Start',
                        stockicon => $PACMain::UNITY ? '' : 'gtk-media-play',
                        code => sub {
                            $PACMain::FUNCS{_MAIN}->_launchTerminals([[$this_uuid]]);
                        }
                    }, {
                        label => "Chain with '$$terminal{_NAME}'",
                        stockicon => $PACMain::UNITY ? '' : 'asbru-chain',
                        sensitive => $$terminal{CONNECTED},
                        code => sub {
                            $terminal->_wSelectChain($this_uuid);
                        }
                    }
                ]
            });
        } else {
            push(@tray_menu_items, {
                label => $this_name,
                stockicon => $PACMain::UNITY ? '' : "asbru-method-$$cfg{'environments'}{$this_uuid}{'method'}",
                tooltip => $$cfg{'environments'}{$this_uuid}{'description'},
                code => sub {
                    $PACMain::FUNCS{_MAIN}->_launchTerminals([[$this_uuid]]);
                }
            });
        }
    }

    return \@tray_menu_items;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Menu — menu-spec builders for tray, sidebar, and chain-with menus

=head1 SYNOPSIS

    use PAC::Menu;

    my $favs = PAC::Menu::favourite_connections();
    my $auto = PAC::Menu::cluster_connections();
    my $tree = PAC::Menu::available_connections();

=head1 DESCRIPTION

Three menu-spec builders that return arrayrefs of hashref menu items,
suitable for feeding into C<_wPopUpMenu> or building C<Gtk3::Menu>
widgets directly.

Mechanical extraction from C<PACUtils::_menuFavouriteConnections>,
C<_menuClusterConnections>, C<_menuAvailableConnections>. PACUtils
retains 1-line goto-proxies under the legacy names.

=head1 PUBLIC API

=over

=item favourite_connections($terminal?)

Returns an arrayref of menu specs for connections marked as favourite
in the user config. Sorted alphabetically by display name. When
C<$terminal> is supplied, each entry has a "Chain with '<terminal>'"
sub-menu.

=item cluster_connections

Returns an arrayref of menu specs for both auto-clusters (defined
in C<defaults.auto cluster>) and saved cluster definitions.

=item available_connections($tree?, $terminal?)

Recursive walker that builds a menu tree mirroring the connections
tree. Groups become sub-menus; leaves become startable items. With
C<$terminal>, leaves get a "Chain with" sub-menu.

=back

=head1 SEE ALSO

L<PACUtils>, L<PAC::Dialog>.

=cut
