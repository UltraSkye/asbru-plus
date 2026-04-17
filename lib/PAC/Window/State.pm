package PAC::Window::State;

###############################################################################
# PAC::Window::State — persist + restore main window position / size
# and the connection-tree pane width.
#
# State stored in $CFG_FILE.gui as a 2-line text file:
#   line 1: "x:y:w:h" or literal "maximized"
#   line 2: "<treepos>"
#
# Mechanical extraction from PACMain::_saveGUIData / _loadGUIData.
# PACMain retains 1-line wrappers.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# save($self) — write current window position / size + tree pane width.
sub save {
    my $self = shift;
    my $path = "$PACMain::CFG_FILE.gui";

    open(my $fh, '>:utf8', $path)
        or die "ERROR: Could not save GUI Config file '$path': $!\n";

    if ($$self{_GUI}{maximized}) {
        print $fh 'maximized';
    } else {
        my ($x, $y) = $$self{_GUI}{main}->get_position();
        my ($w, $h) = $$self{_GUI}{main}->get_size();
        print $fh "$x:$y:$w:$h";

        if ($$self{_VERBOSE}) {
            print STDERR "DEBUG: Saving window position = ($x, $y) ; "
                       . "window size ($w, $h)\n";
        }
    }
    print $fh "\n";

    my $treepos = $$self{_GUI}{hpane}->get_position();
    print $fh "$treepos\n";

    close $fh;
    return 1;
}

# load($self) — read window state from $CFG_FILE.gui into
# $self->{_GUI}{posx,posy,sw,sh,hpanepos}. No-op if file is missing.
sub load {
    my $self = shift;
    my $path = "$PACMain::CFG_FILE.gui";
    return 1 unless -f $path;

    open(my $fh, '<:utf8', $path)
        or die "ERROR: Could not read GUI Config file '$path': $!\n";

    my $win = <$fh>;
    chomp $win;
    if ($win eq 'maximized') {
        ($$self{_GUI}{posx}, $$self{_GUI}{posy},
         $$self{_GUI}{sw},   $$self{_GUI}{sh})
            = ('maximized', 'maximized', 'maximized', 'maximized');
    } else {
        ($$self{_GUI}{posx}, $$self{_GUI}{posy},
         $$self{_GUI}{sw},   $$self{_GUI}{sh}) = split(':', $win);
    }

    if ($$self{_VERBOSE}) {
        print STDERR "DEBUG: Starting window position = "
                   . "($$self{_GUI}{posx}, $$self{_GUI}{posy}) ; "
                   . "window size ($$self{_GUI}{sw}, $$self{_GUI}{sh})\n";
    }

    my $tree = <$fh> // '-1';
    chomp $tree;
    $$self{_GUI}{hpanepos} = $tree;

    close $fh;
    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Window::State — persist + restore main window position/size

=head1 SYNOPSIS

    use PAC::Window::State;

    PAC::Window::State::save($self);    # at shutdown
    PAC::Window::State::load($self);    # at startup, before window show

=head1 DESCRIPTION

Two-line text file at C<\$CFG_FILE.gui> stores the main window's
position + size and the connection-tree pane width across launches.

Mechanical extraction from C<PACMain::_saveGUIData> +
C<_loadGUIData>. PACMain retains 1-line wrappers.

=head1 ON-DISK FORMAT

    line 1:  "x:y:w:h"  or literal "maximized"
    line 2:  "<treepos>"

=head1 PUBLIC API

=over

=item save($self)

Writes the current window state to C<\$PACMain::CFG_FILE.gui>.

=item load($self)

Reads C<\$PACMain::CFG_FILE.gui> into
C<\$self-E<gt>{_GUI}{posx,posy,sw,sh,hpanepos}>. Silent no-op if the
file is missing.

=back

=head1 SEE ALSO

L<PAC::Tree::State> (sibling — tree expanded-state persistence).

=cut
