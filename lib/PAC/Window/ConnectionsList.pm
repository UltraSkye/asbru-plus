package PAC::Window::ConnectionsList;

###############################################################################
# PAC::Window::ConnectionsList — show / hide / toggle the connections-list
# panel (left-side tree pane in Traditional layout, the entire main
# window in Compact layout).
#
# Mechanical extraction from PACMain::_showConnectionsList +
# _hideConnectionsList + _toggleConnectionsList +
# _doToggleDisplayConnectionsList. PACMain retains 1-line wrappers.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# show($self, $force=1) — ensure the connections panel is visible.
# In Compact layout, "the panel" is the whole main window; in
# Traditional layout it is the vboxCommandPanel inside the hpane.
# When $force is true (default), the main window is hidden+shown to
# unstick i3wm "scratchpad" / withdrawn state.
sub show {
    my $self  = shift;
    my $force = shift // 1;

    if ($force) {
        # Force hidden state so that the show operation is properly handled
        # (otherwise the window may remain in the 'scratchpad' / 'withdrawn'
        # state, as with i3wm)
        $$self{_GUI}{main}->hide();
        $$self{_GUI}{main}->show();
    }

    # Ensure compact panel is shown (could still be hidden if started iconified)
    if ($$self{_CFG}{'defaults'}{'layout'} eq 'Compact') {
        $$self{_GUI}{vboxCommandPanel}->show_all();
        $$self{_GUI}{hpane}->show();
    }

    # The first display when started iconified must be a show_all
    if ($$self{_CMDLINETRAY} == 1) {
        $$self{_GUI}{main}->show_all();
        $$self{_CMDLINETRAY} = 2;
    }

    # Do show the main window
    $$self{_GUI}{main}->present();

    if ($force) {
        $$self{_GUI}{main}->move(
            $$self{_GUI}{posx} // 0,
            $$self{_GUI}{posy} // 0,
        );
    }
}

# hide($self) — hide the main window, remembering its current
# position so a later show() can restore it.
sub hide {
    my $self = shift;

    if ($$self{_GUI}{main}->get_visible()) {
        my ($x, $y) = $$self{_GUI}{main}->get_position();
        if ($x > 0 || $y > 0) {
            ($$self{_GUI}{posx}, $$self{_GUI}{posy}) = ($x, $y);
        }
    }

    $$self{_GUI}{main}->hide();
}

# toggle($self) — flip the showConnBtn toolbar button. The button's
# 'toggled' signal then fires apply_toggle() which performs the
# actual show/hide.
sub toggle {
    my $self = shift;
    $$self{_GUI}{showConnBtn}->set_active(
        ! $$self{_GUI}{showConnBtn}->get_active()
    );
}

# apply_toggle($self) — react to the showConnBtn state.
# Compact: show or hide the entire main window via show()/hide().
# Traditional: show or hide the vboxCommandPanel inside the hpane,
# and move keyboard focus to either the tree (when shown) or back
# to the active terminal page (when hidden).
sub apply_toggle {
    my $self = shift;

    if ($$self{_CFG}{'defaults'}{'layout'} eq 'Compact') {
        if ($$self{_GUI}{showConnBtn}->get_active()) {
            $PACMain::FUNCS{_MAIN}->_showConnectionsList();
        } else {
            $PACMain::FUNCS{_MAIN}->_hideConnectionsList();
        }
    } else {
        if ($$self{_GUI}{showConnBtn}->get_active()) {
            $$self{_GUI}{vboxCommandPanel}->show();
        } else {
            $$self{_GUI}{vboxCommandPanel}->hide();
        }
        if ($$self{_GUI}{showConnBtn}->get_active()) {
            # Remember that no VTE has the focus anymore
            $$self{_HAS_FOCUS} = '';
            # Get the currently displayed tray and move keyboard focus to it
            my $tree = $self->_getCurrentTree();
            if ($tree) {
                $tree->grab_focus();
            }
        } else {
            # Look for the current tab page and move keyboard focus to it
            my $pnum = $$self{_GUI}{nb}->get_current_page();
            $self->_doFocusPage($pnum);
        }
    }
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Window::ConnectionsList — show / hide / toggle the connections-list panel

=head1 SYNOPSIS

    use PAC::Window::ConnectionsList;

    PAC::Window::ConnectionsList::show($self);
    PAC::Window::ConnectionsList::hide($self);
    PAC::Window::ConnectionsList::toggle($self);
    PAC::Window::ConnectionsList::apply_toggle($self);

=head1 DESCRIPTION

Manages visibility of the left-side connections tree panel.

In B<Traditional> layout the panel is C<vboxCommandPanel> inside the
horizontal pane; toggling it just shows/hides that widget.

In B<Compact> layout the "panel" is effectively the whole main
window; toggling it hides/shows the toplevel.

Mechanical extraction from C<PACMain::_showConnectionsList> /
C<_hideConnectionsList> / C<_toggleConnectionsList> /
C<_doToggleDisplayConnectionsList>. PACMain retains 1-line wrappers.

=head1 PUBLIC API

=over

=item show($self, $force=1)

Ensure the panel is visible. With C<$force> true (default),
hide+show the main window to unstick window-manager edge cases
(e.g. i3wm scratchpad).

=item hide($self)

Hide the main window, snapshotting its current position into
C<\$self-E<gt>{_GUI}{posx,posy}> so a later C<show()> can restore it.

=item toggle($self)

Flip the C<showConnBtn> toolbar button — the button's signal then
fires C<apply_toggle()>.

=item apply_toggle($self)

React to C<showConnBtn>'s current state. Layout-aware: in Compact,
shows/hides the whole window; in Traditional, shows/hides
C<vboxCommandPanel> and moves keyboard focus appropriately.

=back

=head1 SEE ALSO

L<PAC::Window::Layout>, L<PAC::Window::State>, L<PAC::Terminal::Focus>.

=cut
