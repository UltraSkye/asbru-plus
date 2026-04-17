package PAC::Util::TreeSelection;

###############################################################################
# PAC::Util::TreeSelection — Gtk2-style get_selected_rows() helper.
#
# Gtk3's TreeSelection::get_selected_rows returns C<($paths, $model)>
# where the legacy Gtk2 API returned just C<@paths>. This helper
# restores the Gtk2 calling convention for the 10+ callsites that
# expect it.
#
# Mechanical extraction from PACUtils::_getSelectedRows. PACUtils
# retains a 1-line goto-proxy.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# rows($tree_selection) — returns the list of selected paths.
# Returns the empty list if nothing selected.
sub rows {
    my $tree_selection = shift;
    my ($aref, undef) = $tree_selection->get_selected_rows();
    return () unless $aref;
    return @$aref;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Util::TreeSelection — Gtk2-style get_selected_rows() helper

=head1 SYNOPSIS

    use PAC::Util::TreeSelection;

    my @paths = PAC::Util::TreeSelection::rows($selection);
    for my $path (@paths) { ... }

=head1 DESCRIPTION

Gtk3's L<Gtk3::TreeSelection>::get_selected_rows returns
C<($paths, $model)>; the legacy Gtk2 API returned just C<@paths>.
This helper restores the Gtk2 calling convention.

Mechanical extraction from C<PACUtils::_getSelectedRows>. PACUtils
retains a 1-line goto-proxy under the legacy name.

=head1 PUBLIC API

=over

=item rows($tree_selection)

Returns the list of selected C<Gtk3::TreePath> objects from the
given C<Gtk3::TreeSelection>. Empty list if nothing selected.

=back

=head1 SEE ALSO

L<Gtk3::TreeSelection>.

=cut
