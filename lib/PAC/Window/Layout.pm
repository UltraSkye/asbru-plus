package PAC::Window::Layout;

###############################################################################
# PAC::Window::Layout — main window layout switcher (Traditional ↔ Compact).
#
# Two helpers extracted from PACMain:
#
#   - set_safe_options($self, $layout)
#       Mutates \$self->{_CFG}{defaults} to enforce config invariants
#       required by the chosen layout. Backs up the traditional settings
#       in 'lt …' keys before switching to Compact, restores them when
#       switching back.
#
#   - apply($self, $layout)
#       Applies the layout to the actual window/widgets — hides
#       toolbar buttons, resizes the main window, sets the popup-menu
#       hint, etc. Currently only the 'Compact' branch does anything;
#       'Traditional' is the default state.
#
# Mechanical extraction from PACMain::_setSafeLayoutOptions and
# _ApplyLayout. PACMain retains 1-line proxies.
###############################################################################

use strict;
use warnings;
use utf8;

use Gtk3;

our $VERSION = '0.1.0';

# set_safe_options($self, $layout)
sub set_safe_options {
    my ($self, $layout) = @_;
    my $cfg = $$self{_CFG}{'defaults'};

    if ($layout eq 'Compact') {
        # Compact requires these specific settings
        $cfg->{'tabs in main window'}        = 0;
        $cfg->{'auto hide connections list'} = 0;
        if (!$PACMain::STRAY) {
            $cfg->{'start iconified'} = 0;
        } else {
            $cfg->{'close to tray'} = 1;
        }
    } else {
        # Traditional: back up or restore the 'lt …' shadow keys
        if (!defined $cfg->{'layout traditional settings'}
            || $cfg->{'layout previous'} eq $layout)
        {
            # Save current Traditional values that Compact would clobber
            $cfg->{'lt tabs in main window'} = $cfg->{'tabs in main window'};
            $cfg->{'layout traditional settings'} = 1;
            $cfg->{'lt start iconified'} = $cfg->{'start iconified'};
            $cfg->{'lt close to tray'}   = $cfg->{'close to tray'};
            $cfg->{'lt auto save'}       = $cfg->{'auto save'};
        } elsif ($cfg->{'layout previous'} ne $layout) {
            # Returning from Compact — restore the saved Traditional values
            $cfg->{'tabs in main window'} = $cfg->{'lt tabs in main window'};
            $cfg->{'start iconified'}     = $cfg->{'lt start iconified'};
            $cfg->{'close to tray'}       = $cfg->{'lt close to tray'};
            $cfg->{'auto save'}           = $cfg->{'lt auto save'};
        }
    }
    $cfg->{'layout previous'} = $layout;
    return 1;
}

# apply($self, $layout)
sub apply {
    my ($self, $layout) = @_;

    return 1 unless $layout eq 'Compact';

    my $H = Gtk3::Gdk::Screen::get_default()->get_height() - 100;
    $$self{wheight} = 600;
    $$self{wheight} = int($H * 0.8) if $H < $$self{wheight};

    foreach my $e ('hbuttonbox1', 'connSearch', 'connExecBtn',
                   'connQuickBtn', 'connFavourite',
                   'vboxConnectionPanel', 'vboxInfo')
    {
        $$self{_GUI}{$e}->hide();
    }

    if (!$PACMain::STRAY) {
        $self->_showConnectionsList() unless $$self{_GUI}{main}->get_visible();
    } else {
        $self->_hideConnectionsList() if $$self{_GUI}{main}->get_visible();
        $$self{_GUI}{main}->set_type_hint('popup-menu');
    }

    $$self{_GUI}{main}->set_default_size(220, $$self{wheight});
    $$self{_GUI}{main}->resize(220, $$self{wheight});
    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Window::Layout — main window layout switcher (Traditional/Compact)

=head1 SYNOPSIS

    use PAC::Window::Layout;

    PAC::Window::Layout::set_safe_options($self, 'Compact');
    PAC::Window::Layout::apply($self, 'Compact');

=head1 DESCRIPTION

Two layout-machinery helpers extracted from PACMain. C<set_safe_options>
mutates config invariants required for a given layout (and shadows the
Traditional values in 'lt …' keys so Compact can be reverted cleanly).
C<apply> performs the actual UI changes (hide toolbar buttons, resize
window, set popup-menu hint).

Mechanical extraction from C<PACMain::_setSafeLayoutOptions> +
C<_ApplyLayout>. PACMain retains 1-line wrappers.

=head1 PUBLIC API

=over

=item set_safe_options($self, $layout)

Adjusts C<\$self-E<gt>{_CFG}{defaults}> to satisfy the layout's
invariants. Returns 1.

=item apply($self, $layout)

Applies the layout to the actual main window / widgets. Currently
only C<Compact> does anything; Traditional is the default state.
Returns 1.

=back

=head1 SEE ALSO

L<PAC::Theme::Switch>, L<PAC::Window::State>.

=cut
