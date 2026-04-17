package PAC::Tree::State;

###############################################################################
# PAC::Tree::State — persist + restore the connection-tree expanded
# state and notebook-tab order.
#
# State is stored in $CFG_FILE.tree (a flat text file alongside the
# main yaml config). One line per item:
#   - <uuid>                 a node that was expanded
#   - tree_page_N:scrollX    the scroll widget at notebook page N
#   - tree_page_N:vboxclu    the cluster vbox at notebook page N
#
# Mechanical extraction from PACMain::_saveTreeExpanded /
# _loadTreeExpanded. PACMain retains 1-line wrappers.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# save($self, $tree?) — write the current expanded state + notebook
# order to $PACMain::CFG_FILE.tree. $tree defaults to
# $self->{_GUI}{treeConnections}.
sub save {
    my $self = shift;
    my $tree = shift // $$self{_GUI}{treeConnections};

    my $modelsort = $tree->get_model();
    my $path_file = "$PACMain::CFG_FILE.tree";

    open(my $fh, '>:utf8', $path_file)
        or die "ERROR: Could not save Tree Config file '$path_file': $!\n";

    $modelsort->foreach(sub {
        my ($store, $path, $iter, undef) = @_;
        my $uuid = $store->get_value($iter, 2);
        return 0 unless $tree->row_expanded($path) && $uuid ne '__PAC__ROOT__';
        print $fh $uuid . "\n";
        return 0;
    });

    # Notebook page order — record which scroll/vbox widget is at each
    # of the 4 page positions, so load() can restore the user's
    # arrangement.
    my @widgets = (
        ['scroll1', $$self{_GUI}{scroll1}],
        ['scroll2', $$self{_GUI}{scroll2}],
        ['scroll3', $$self{_GUI}{scroll3}],
        ['vboxclu', $$self{_GUI}{vboxclu}],
    );
    for my $page_idx (0 .. 3) {
        my $page = $$self{_GUI}{nbTree}->get_nth_page($page_idx);
        for my $entry (@widgets) {
            my ($name, $w) = @$entry;
            print $fh "tree_page_${page_idx}:${name}\n" if $w && $w eq $page;
        }
    }

    close $fh;
    return 1;
}

# load($self, $tree?) — restore expanded state + notebook order from
# $PACMain::CFG_FILE.tree. Silent no-op if the file doesn't exist.
sub load {
    my $self = shift;
    my $tree = shift // $$self{_GUI}{treeConnections};

    my $path_file = "$PACMain::CFG_FILE.tree";
    return 1 unless -f $path_file;

    my %tabs;
    open(my $fh, '<:utf8', $path_file)
        or die "ERROR: Could not read Tree Config file '$path_file': $!\n";
    while (my $line = <$fh>) {
        chomp $line;
        if ($line =~ /^tree_page_(\d):(.+)$/o) {
            $tabs{$1} = $2;
        } else {
            my $path = $$self{_GUI}{treeConnections}->_getPath($line) or next;
            $tree->expand_row($path, 0);
        }
    }
    close $fh;

    for my $idx (0 .. 3) {
        next unless defined $tabs{$idx};
        my $w = $$self{_GUI}{$tabs{$idx}};
        $$self{_GUI}{nbTree}->reorder_child($w, $idx) if $w;
    }

    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Tree::State — persist + restore connection tree expanded state

=head1 SYNOPSIS

    use PAC::Tree::State;

    PAC::Tree::State::save($self);   # at shutdown
    PAC::Tree::State::load($self);   # at startup

=head1 DESCRIPTION

The connection tree's expanded state and notebook-tab order are
persisted to C<\$CFG_FILE.tree> alongside the main config so the user's
view layout survives across launches.

Mechanical extraction from C<PACMain::_saveTreeExpanded> +
C<_loadTreeExpanded>. PACMain retains 1-line wrappers.

The on-disk format is one line per item:

    <uuid>               a tree node that was expanded
    tree_page_N:scrollX  the scroll widget at notebook page N
    tree_page_N:vboxclu  the cluster vbox at notebook page N

=head1 PUBLIC API

=over

=item save($self, $tree?)

Walks the tree model, writes one line per expanded node + the four
notebook-page bindings. C<\$tree> defaults to
C<\$self-E<gt>{_GUI}{treeConnections}>.

=item load($self, $tree?)

Reads C<\$PACMain::CFG_FILE.tree> and re-expands the recorded nodes,
re-orders the notebook tabs. Silent no-op if the file is missing.

=back

=head1 SEE ALSO

L<PACMain>.

=cut
