package PAC::Dialog::PopupMenu;

###############################################################################
# PAC::Dialog::PopupMenu — context-menu builder via Gtk3::UIManager.
#
# Mechanical extraction of PACUtils::_wPopUpMenu (122 lines) and its
# two nested helpers (_buildMenuData, _pos). The originals used
# PACUtils package globals (\$jari, \$event) for cross-helper state;
# here they become module-scoped lexicals for cleaner ownership.
#
# PACUtils retains a 1-line proxy (sub _wPopUpMenu { goto &show; }).
# Existing 11+ callsites in PACMain, PACScripts, PACScreenshots,
# PACTerminal, PACTrayUnity, lib/method/PACMethod_*.pm work unchanged.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;

our $VERSION = '0.1.0';

# Module-scoped state (was: $PACUtils::WIDGET_POPUP, our $jari, our $event).
my $WIDGET_POPUP;
my $JARI = -1;       # action-name counter (incremented per item)
my $EVENT;           # the click event, used by _pos for placement

# show($menu_ref, $event?, $below?, $ref_only?)
# Builds a Gtk3 popup menu from $menu_ref (arrayref of menu specs)
# and pops it up at the event location. With $below truthy, places
# below the source widget instead of at the cursor. With $ref_only,
# returns the constructed widget WITHOUT popping it up (used by
# PACTrayUnity to attach to AppIndicator).
sub show {
    my $mref     = shift;
    $EVENT       = shift;
    my $below    = shift // 0;
    my $ref_only = shift // 0;

    return 1 if defined $WIDGET_POPUP && $WIDGET_POPUP->get_visible();

    $JARI = -1;
    my @array;
    my %props;

    my $xml = "<ui>\n<popup name='Menu' accelerators='true'>\n";
    $xml .= _build_menu_data(\@array, $mref, \%props);
    $xml .= "</popup>\n</ui>";

    my $actions = Gtk3::ActionGroup->new('Actions');
    $actions->add_actions(\@array, undef);

    my $ui = Gtk3::UIManager->new();
    $ui->set_add_tearoffs(1);
    $ui->insert_action_group($actions, 0);
    $ui->add_ui_from_string($xml);

    foreach my $path (keys %props) {
        foreach my $prop (keys %{$props{$path}}) {
            $ui->get_widget('/Menu' . $path)->set($prop, $props{$path}{$prop});
        }
    }

    $WIDGET_POPUP = $ui->get_widget('/Menu');
    $WIDGET_POPUP->show_all();

    return $WIDGET_POPUP if $ref_only;

    if (defined $EVENT) {
        $WIDGET_POPUP->popup(undef, undef, ($below ? \&_pos : undef), undef,
            $EVENT->button, $EVENT->time);
    } else {
        $WIDGET_POPUP->popup(undef, undef, undef, undef, 0, 0);
    }

    return 1;
}

# Internal: recursive XML+actions builder.
sub _build_menu_data {
    my ($menu_array, $mref, $props, $path) = @_;
    $path //= '';
    my $xml = '';

    for my $m (@{$mref}) {
        my $label     = $m->{label} // '';
        my $sensitive = $m->{sensitive} // 1;
        my $tooltip   = $m->{tooltip} // '';
        $m->{shortcut} //= '';

        my $label_orig = PACUtils::__text($label);
        $label =~ s/\//__backslash__/go;
        my $pre_path = $path;

        ++$JARI;
        if ($m->{separator}) {
            $xml .= "<separator/>\n";
        } elsif ($m->{submenu}) {
            $xml .= qq|<menu action="MenuParent@{[PACUtils::__($label)]}:$JARI:EndMenuParent">\n|;
            push @$menu_array, ["MenuParent$label:$JARI:EndMenuParent",
                                $m->{stockicon}, $label_orig];

            $path .= "/MenuParent$label:$JARI:EndMenuParent";
            $props->{$path}{sensitive}    = $sensitive;
            $props->{$path}{tooltip_text} = $tooltip;
            $props->{$path}{use_underline} = 0;

            $xml .= _build_menu_data($menu_array, $m->{submenu}, $props, $path);
            $xml .= "</menu>\n";
        } else {
            $xml .= qq|<menuitem action="MenuItem@{[PACUtils::__($label)]}:$JARI:EndMenuItem"/>|
                  . "\n";
            push @$menu_array, [
                "MenuItem$label:$JARI:EndMenuItem",
                $m->{stockicon},
                $label_orig,
                $m->{shortcut},
                $m->{tooltip},
                sub { &{$m->{code}}; },
            ];

            $path .= "/MenuItem$label:$JARI:EndMenuItem";
            $props->{$path}{sensitive}    = $sensitive;
            $props->{$path}{tooltip_text} = $tooltip;
            $props->{$path}{use_underline} = 0;
        }

        $path = $pre_path;
    }

    return $xml;
}

# Internal: position-callback for "below the source widget".
sub _pos {
    my $h    = $_[0]->size_request->height;
    my $ymax = $EVENT->get_screen()->get_height();
    my ($x, $y) = $EVENT->window->get_origin();
    my $dy   = $EVENT->window->get_height();

    if ($dy + $y + $h > $ymax) {
        $y -= $h;
        $y  = 0 if $y < 0;
    } else {
        $y += $dy;
    }
    return ($x, $y);
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Dialog::PopupMenu — context-menu builder via Gtk3::UIManager

=head1 SYNOPSIS

    use PAC::Dialog::PopupMenu;

    my @items = (
        { label => 'Connect', code => sub { ... } },
        { label => 'Edit',    code => sub { ... } },
        { separator => 1 },
        {
            label   => 'More',
            submenu => [
                { label => 'Duplicate', code => sub { ... } },
                { label => 'Delete',    code => sub { ... } },
            ],
        },
    );
    PAC::Dialog::PopupMenu::show(\@items, $event);

    # Reference-only mode (for AppIndicator menu attach):
    my $widget = PAC::Dialog::PopupMenu::show(\@items, $event, 0, 1);

=head1 DESCRIPTION

Mechanical extraction of C<PACUtils::_wPopUpMenu>. Builds a popup menu
from an arrayref of hashref menu specs and shows it at the event
location.

Each menu item supports: C<label>, C<stockicon>, C<tooltip>,
C<shortcut>, C<sensitive>, C<code> (callback), C<separator>,
C<submenu> (recursive).

=head1 PUBLIC API

=over

=item show($menu_ref, $event?, $below?, $ref_only?)

Builds and pops up the menu. C<$event> is the Gtk button event used
for positioning; if undef, popup at (0,0). With C<$below> truthy,
places the menu below the source widget instead of at the cursor.
With C<$ref_only>, returns the constructed widget WITHOUT popping
it up (used to attach to AppIndicator).

If a popup is already visible, returns 1 without doing anything
(prevents popup-stacking).

=back

=head1 SEE ALSO

L<Gtk3::UIManager>, L<PACUtils>.

=cut
