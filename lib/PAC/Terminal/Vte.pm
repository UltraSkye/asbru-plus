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

# probe($self) — populate $self->{_Vte}{...} with runtime-detected
# capability flags. Called once at PACMain startup; the flags are
# read by feed/feed_child/feed_child_binary above and by PACTerminal
# for match_regex / get_text_range support.
#
# Mechanical extraction from PACMain::_setVteCapabilities. PACMain
# retains a 1-line wrapper.
sub probe {
    my $self = shift;
    require Vte;
    my $vte = Vte::Terminal->new();

    local $SIG{__WARN__} = sub {};
    $self->{_Vte}{major_version} = Vte::get_major_version();
    $self->{_Vte}{minor_version} = Vte::get_minor_version();

    # set_bold_is_bright — added in VTE 0.52.
    $self->{_Vte}{has_bright} = 0;
    eval {
        $vte->set_bold_is_bright(0);
        $self->{_Vte}{has_bright} = 1;
    };

    # feed_child(): 1-arg (VTE 0.52+) vs 2-arg (older). Some Ubuntu
    # VTE 0.52 packages were patched to keep the 2-arg signature, so
    # we probe instead of trusting version numbers.
    # See: https://bugs.launchpad.net/ubuntu/+source/ubuntu-release-upgrader/+bug/1780501
    $self->{_Vte}{vte_feed_child} = 0;
    eval {
        local $SIG{__WARN__} = sub { die @_ };
        $vte->feed_child('abc', 3);
        1;
    } or do {
        $self->{_Vte}{vte_feed_child} = 1;
    };

    # feed_child_binary: 1-arg as of v0.46. (Version check is enough
    # here — no known patched downstreams.)
    $self->{_Vte}{vte_feed_binary} = 0;
    if ($self->{_Vte}{major_version} >= 1
        || $self->{_Vte}{minor_version} >= 46)
    {
        $self->{_Vte}{vte_feed_binary} = 1;
    }

    # Runtime probe for match_add_regex (VTE 0.46+).
    $self->{_Vte}{match_regex} = 0;
    eval {
        $vte->match_add_regex(Vte::Regex->new_for_match('.', -1, 2 ** 10), 0);
        $self->{_Vte}{match_regex} = 1;
    };

    # Runtime probe for get_text_range_format (VTE 0.72+).
    $self->{_Vte}{get_text_range} = 0;
    eval {
        $vte->get_text_range_format('VTE_FORMAT_TEXT', 0, 0, 0, 0);
        $self->{_Vte}{get_text_range} = 1;
    };

    print STDERR "INFO: Virtual terminal emulator (VTE) version is "
               . "$self->{_Vte}{major_version}.$self->{_Vte}{minor_version}\n";
    if ($self->{_VERBOSE}) {
        foreach my $k (sort keys %{$self->{_Vte}}) {
            print STDERR "       - $k = $self->{_Vte}{$k}\n";
        }
    }
    return 1;
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

=item probe($self)

Populates C<\$self-E<gt>{_Vte}{...}> with runtime-detected capability
flags (major/minor version, has_bright, vte_feed_child, vte_feed_binary,
match_regex, get_text_range). Called once at PACMain startup.

Probes by C<eval>-ing the actual API rather than trusting version
numbers (some Ubuntu/Debian backports keep the older signatures).

=back

=head1 SEE ALSO

L<Vte>, L<PACMain/_setVteCapabilities>.

=cut
