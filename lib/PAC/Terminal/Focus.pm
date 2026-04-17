package PAC::Terminal::Focus;

###############################################################################
# PAC::Terminal::Focus — bring keyboard focus to the terminal that
# owns the just-activated notebook tab page.
#
# Mechanical extraction of PACMain::_doFocusPage. PACMain retains a
# 1-line wrapper. The function is wired from the notebook's
# 'switch-page' signal (callbacks.pm).
#
# Side effects on the matching RUNNING entry:
#   - tree cursor moves to the connection's UUID
#   - terminal's tab colour is refreshed
#   - X11 window focus moves to the FOCUS widget (if not embedded)
#   - VTE widget grabs Gtk focus
#   - $self->{_HAS_FOCUS} stores the VTE widget for later use
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# focus_page($self, $pnum) — find the terminal whose container widget
# matches notebook page $pnum, then focus it.
sub focus_page {
    my ($self, $pnum) = @_;
    my $tab_page = $$self{_GUI}{nb}->get_nth_page($pnum);

    $$self{_HAS_FOCUS} = '';
    foreach my $tmp_uuid (keys %PACMain::RUNNING) {
        my $term = $PACMain::RUNNING{$tmp_uuid}{terminal};
        next unless $term;

        my $check_gui = $term->{_SPLIT}
            ? $term->{_SPLIT_VPANE}
            : $term->{_GUI}{_VBOX};
        next unless defined $check_gui && $check_gui eq $tab_page;

        # Sync tree cursor to the connection's UUID
        my $uuid = $PACMain::RUNNING{$tmp_uuid}{uuid};
        my $path = $$self{_GUI}{treeConnections}->_getPath($uuid);
        if ($path) {
            $$self{_GUI}{treeConnections}->expand_to_path($path);
            $$self{_GUI}{treeConnections}->set_cursor($path, undef, 0);
        }

        $term->_setTabColour();

        if (!$term->{EMBED}) {
            eval {
                my $win = $term->{FOCUS}->get_window();
                $win->focus(time) if defined $win;
            };
            $term->{_GUI}{_VTE}->grab_focus();
        }
        $$self{_HAS_FOCUS} = $term->{_GUI}{_VTE};

        last;     # found it; stop scanning
    }
    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Terminal::Focus — focus the terminal owning a notebook tab page

=head1 SYNOPSIS

    use PAC::Terminal::Focus;

    # Wired from the notebook's 'switch-page' signal
    PAC::Terminal::Focus::focus_page($self, $page_num);

=head1 DESCRIPTION

When the user switches to a different tab in the main notebook,
this finds the terminal whose container widget matches that page
and brings keyboard focus to its VTE. Also moves the connections-
tree cursor to the matching UUID and refreshes the tab colour.

Mechanical extraction from C<PACMain::_doFocusPage>; PACMain retains
a 1-line wrapper.

=head1 PUBLIC API

=over

=item focus_page($self, $page_num)

Walks C<%PACMain::RUNNING> looking for the terminal whose container
widget is the notebook page at C<\$page_num>. When found:

=over

=item *

Moves the tree cursor to that connection's UUID

=item *

Refreshes the terminal's tab colour

=item *

Focuses the X11 window of the FOCUS widget (if not embedded)

=item *

VTE widget grabs Gtk focus

=item *

C<\$self-E<gt>{_HAS_FOCUS}> stores the VTE widget

=back

Returns 1.

=back

=head1 SEE ALSO

L<PAC::Terminal::Vte>, L<Gtk3::Notebook>.

=cut
