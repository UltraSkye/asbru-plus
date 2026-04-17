package PAC::Tree::Sort;

###############################################################################
# PAC::Tree::Sort — comparator for sorting connection-tree nodes.
#
# Public API uses explicit-args form (compare_pair($x, $y)) so callers
# can use it via a sort block from any package without worrying about
# the package-global $a/$b semantics:
#
#     use PAC::Tree::Sort;
#     my @sorted = sort { PAC::Tree::Sort::compare_pair($a, $b) } @nodes;
#
# A legacy `compare` form (using package globals \$a/\$b) is kept for
# backward compat with the PACUtils::_sortTreeData proxy, which exists
# so existing test code in t/16 continues to work unchanged.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.2.0';

# 'our' declarations so the legacy `compare` form's $a/$b reference
# strict-clean. Perl's `sort SUBNAME` sets these in the CALLER's
# package, not ours — that's why we prefer compare_pair() for new
# call sites.
our ($a, $b);

# compare_pair($x, $y) — explicit-args form. Returns -1/0/+1.
sub compare_pair {
    my ($x, $y) = @_;
    my $cfg = $PACMain::FUNCS{_MAIN}{_CFG};
    my $groups_1st = $$cfg{'defaults'}{'sort groups first'} // 1;

    my $x_name = lc($$x{'value'}[1]);
    $x_name =~ s/<.+>(.+?)<\/.+>/$1/go;
    my $y_name = lc($$y{'value'}[1]);
    $y_name =~ s/<.+>(.+?)<\/.+>/$1/go;
    my $x_is_group = $$cfg{'environments'}{$$x{'value'}[2]}{'_is_group'};
    my $y_is_group = $$cfg{'environments'}{$$y{'value'}[2]}{'_is_group'};

    if ($groups_1st) {
        return -1 if  $x_is_group && !$y_is_group;
        return  1 if !$x_is_group &&  $y_is_group;
        return $x_name cmp $y_name;
    }
    return $x_name cmp $y_name;
}

# compare — package-globals form ($a/$b in PAC::Tree::Sort namespace).
# Used by the legacy PACUtils::_sortTreeData proxy (which is called by
# t/16 with $PACUtils::a/b set explicitly). Forwards to compare_pair().
sub compare { return compare_pair($a, $b); }

1;

__END__

=encoding utf8

=head1 NAME

PAC::Tree::Sort — comparator for sorting connection-tree nodes

=head1 PUBLIC API

=over

=item compare_pair($x, $y)

Explicit-args comparator. Returns -1/0/+1. Use this from any package:

    use PAC::Tree::Sort;
    my @sorted = sort { PAC::Tree::Sort::compare_pair($a, $b) } @nodes;

=item compare

Legacy package-globals comparator (uses C<\$PAC::Tree::Sort::a/b>).
Kept for backward compat with the C<PACUtils::_sortTreeData> proxy
that t/16 relies on. New call sites should prefer C<compare_pair>.

=back

=head1 LEGACY

=head1 SYNOPSIS

    use PAC::Tree::Sort;

    my @sorted = sort PAC::Tree::Sort::compare @tree_nodes;

=head1 DESCRIPTION

Mechanical extraction of C<PACUtils::_sortTreeData>. Sorts tree nodes
case-insensitively by visible name. When C<defaults.{sort groups first}>
is true (default), groups come before connections.

PACUtils retains an alias under C<_sortTreeData> so the legacy callsite
in L<PAC::Menu> continues to work unchanged.

=head1 PUBLIC API

=over

=item compare

Sort comparator using C<\$a> and C<\$b> (set by Perl's C<sort> in this
module's package). Strips HTML tags from node names before comparing.
Returns -1/0/+1.

=back

=head1 SEE ALSO

L<perlfunc/sort>, L<PACUtils>.

=cut
