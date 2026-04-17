package PAC::Terminal::Vte;

###############################################################################
# PAC::Terminal::Vte — wrappers for VTE feed/feed_child/feed_child_binary.
#
# VTE 0.46+ changed the calling convention for these methods (single-arg
# vs string+length). We probe at startup which version is available
# (PACMain::_setVteCapabilities populates $PACMain::FUNCS{_MAIN}{_Vte}{...})
# and dispatch accordingly. This module hides the conditional from
# callers.
#
# Mechanical extraction from PACUtils. PACUtils retains 1-line proxies
# for the legacy underscored names.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# feed($vte, $string)
# Feed bytes to the VTE terminal as if they came from the child process.
# Used for displaying messages in the terminal area.
sub feed {
    my ($vte, $str) = @_;
    my @arr = unpack('C*', $str);
    $vte->feed(\@arr);
}

# feed_child($vte, $string)
# Feed bytes to the child as if they came from the user's keyboard.
# Used for sending macros, expect responses, paste content.
sub feed_child {
    my ($vte, $str) = @_;
    my $feed_version = $PACMain::FUNCS{_MAIN}{_Vte}{vte_feed_child};

    use bytes;
    my $b = length($str);
    my @arr = unpack('C*', $str);

    if ($feed_version == 1) {
        $vte->feed_child(\@arr);          # VTE 0.46+
    } else {
        $vte->feed_child($str, $b);       # VTE pre-0.46
    }
}

# feed_child_binary($vte, $bytes)
# Like feed_child but explicitly binary-safe (no charset conversion).
sub feed_child_binary {
    my ($vte, $str) = @_;
    my @arr = unpack('C*', $str);
    my $feed_version = $PACMain::FUNCS{_MAIN}{_Vte}{vte_feed_binary};

    if ($feed_version == 1) {
        $vte->feed_child_binary(\@arr);
    } else {
        $vte->feed_child_binary(\@arr, length(\@arr));
    }
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Terminal::Vte — version-tolerant wrappers for VTE feed methods

=head1 SYNOPSIS

    use PAC::Terminal::Vte;

    PAC::Terminal::Vte::feed($vte, "\033[2J");        # clear screen
    PAC::Terminal::Vte::feed_child($vte, "ls -la\n"); # type as user
    PAC::Terminal::Vte::feed_child_binary($vte, $raw);

=head1 DESCRIPTION

Hides the VTE 0.46+ vs pre-0.46 calling convention difference for
the feed family of methods. The dispatch flag is populated at startup
by C<PACMain::_setVteCapabilities> via runtime probing.

Mechanical extraction from C<PACUtils>. PACUtils retains 1-line
goto-proxies under the legacy names (C<_vteFeed>, C<_vteFeedChild>,
C<_vteFeedChildBinary>).

=head1 PUBLIC API

=over

=item feed($vte, $string)

Feeds bytes to the terminal display as if they came from the child.

=item feed_child($vte, $string)

Feeds bytes to the child process as if typed at the keyboard.

=item feed_child_binary($vte, $string)

Like C<feed_child> but explicitly binary-safe.

=back

=head1 SEE ALSO

L<Vte>, L<PACMain/_setVteCapabilities>.

=cut
