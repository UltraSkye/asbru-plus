package PAC::Net::WindowList;

###############################################################################
# PAC::Net::WindowList — enumerate top-level X11 windows via Wnck.
#
# Mechanical extraction from PACUtils::_getXWindowsList. PACUtils retains
# a 1-line goto-proxy.
#
# Used by terminal-embed code in PACTerminal to find target windows by
# name (e.g. for kidnap-style window grabbing into our tab area).
###############################################################################

use strict;
use warnings;
use utf8;

use Wnck;

our $VERSION = '0.1.0';

# all() — returns a hashref of:
#   { by_xid  => { $xid  => { title, window } },
#     by_name => { $name => { xid,   window } } }
# where 'window' is the Wnck::Window object.
sub all {
    my %list;

    my $screen = Wnck::Screen::get_default() or die "Wnck::Screen unavailable: $!";
    $screen->force_update();

    foreach my $w (@{$screen->get_windows}) {
        my $xid = $w->get_xid() or next;
        my $name = $w->get_name();

        $list{by_xid}{$xid}{title}  = $name;
        $list{by_xid}{$xid}{window} = $w;

        if (defined $name) {
            $list{by_name}{$name}{xid}    = $xid;
            $list{by_name}{$name}{window} = $w;
        }
    }

    return \%list;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Net::WindowList — enumerate top-level X11 windows via Wnck

=head1 SYNOPSIS

    use PAC::Net::WindowList;

    my $w = PAC::Net::WindowList::all();
    for my $title (sort keys %{$w->{by_name}}) {
        my $xid = $w->{by_name}{$title}{xid};
        printf "%-40s %d\n", $title, $xid;
    }

=head1 DESCRIPTION

Lists every top-level X11 window currently on the default screen,
indexed by both XID and window title. Wraps L<Wnck>'s screen-windows
API. Used by terminal-embed code to find target windows for grabbing
into our tab area.

Mechanical extraction from C<PACUtils::_getXWindowsList>. PACUtils
retains a 1-line goto-proxy.

=head1 PUBLIC API

=over

=item all

Returns a hashref:

    { by_xid  => { $xid  => { title => $title, window => $wnck_window } },
      by_name => { $name => { xid   => $xid,   window => $wnck_window } } }

Dies if Wnck::Screen is unavailable (e.g. running under Wayland
without xwayland-wnck shim).

=back

=head1 SEE ALSO

L<Wnck>, L<https://wiki.gnome.org/Projects/libwnck>.

=cut
