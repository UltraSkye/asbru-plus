package PAC::Tree::Build;

###############################################################################
# PAC::Tree::Build — build the connections-tree's data array from
# $CFG{environments}.
#
# Mechanical extraction from PACMain::_loadTreeConfiguration +
# PACMain::__recurLoadTree. PACMain retains 1-line proxies.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# load($self, $group=undef, $tree=$self->{_GUI}{treeConnections})
# — wipe and rebuild the connections tree's data model from
# $CFG{environments}{__PAC__ROOT__}{children}, then move the
# selection cursor to the root path.
#
# $group is accepted for backward compatibility with the legacy
# signature but is unused (the root node is always the source).
sub load {
    my $self  = shift;
    my $group = shift;       # legacy signature — unused
    my $tree  = shift // $$self{_GUI}{treeConnections};

    @{ $$self{_GUI}{treeConnections}{'data'} } = ({
        value    => [
            $PACMain::GROUPICON_ROOT,
            '<b>My Connections</b>',
            '__PAC__ROOT__',
        ],
        children => [],
    });

    foreach my $child (
        keys %{ $$self{_CFG}{environments}{'__PAC__ROOT__'}{children} }
    ) {
        push @{ $$tree{data} }, recur_load($self, $child);
    }

    # Select the root path
    $tree->set_cursor($tree->_getPath('__PAC__ROOT__'), undef, 0);

    return 1;
}

# recur_load($self, $uuid) — recursively build the data sub-array
# for one tree node. Returns a list of one element (so callers can
# safely push the result into a flat array).
#
# Leaf nodes get the per-method icon; group nodes recurse into
# their children and use the closed-folder icon.
#
# Re-uses $self->__treeBuildNodeName(...) (still a PACMain method)
# for the display label so right-click "rename" + name-decoration
# logic stays in one place.
sub recur_load {
    my $self = shift;
    my $uuid = shift;

    my $node_name = $self->__treeBuildNodeName($uuid);
    my @list;

    if (!$$self{_CFG}{environments}{$uuid}{'_is_group'}) {
        push @list, {
            value => [
                $$self{_METHODS}{ $$self{_CFG}{'environments'}{$uuid}{'method'} }{'icon'},
                $node_name,
                $uuid,
            ],
            children => [],
        };
    } else {
        my @clist;
        foreach my $child (
            keys %{ $$self{_CFG}{environments}{$uuid}{children} }
        ) {
            push @clist, recur_load($self, $child);
        }
        push @list, {
            value    => [ $PACMain::GROUPICONCLOSED, $node_name, $uuid ],
            children => \@clist,
        };
    }

    return @list;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Tree::Build — build the connections-tree's data array from CFG

=head1 SYNOPSIS

    use PAC::Tree::Build;

    PAC::Tree::Build::load($self);
    PAC::Tree::Build::load($self, undef, $tree);

=head1 DESCRIPTION

Walks C<$CFG{environments}{__PAC__ROOT__}{children}> recursively
to build the data array consumed by the C<PACTree> Gtk widget,
then moves the selection cursor to the root path.

Mechanical extraction from C<PACMain::_loadTreeConfiguration> +
C<PACMain::__recurLoadTree>. PACMain retains 1-line proxies.

=head1 PUBLIC API

=over

=item load($self, $group=undef, $tree=$self->{_GUI}{treeConnections})

Wipe and rebuild the connections tree's data model. The C<$group>
argument is accepted for backward compatibility with the legacy
signature but is unused (the root node is always the source).

=item recur_load($self, $uuid)

Recursively build the data sub-array for one tree node. Returns a
list of one element so the caller can push into a flat array.

=back

=head1 SEE ALSO

L<PAC::Tree::Sort>, L<PAC::Tree::State>.

=cut
