package PAC::Util::Readme;

###############################################################################
# PAC::Util::Readme — parse the latest-version README placed in the
# config tmp dir to detect changes.
#
# The launcher writes a fresh copy of the project README to
# \$CFG_DIR/tmp/latest_README at startup. This module reads it and
# extracts (version, change-list) from a known line offset (line 56 =
# version, lines 54+ = changelog block). Used by the "what's new"
# popup at first launch after upgrade.
#
# Mechanical extraction from PACUtils::_checkREADME. PACUtils retains
# a 1-line goto-proxy.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# check() — returns ($version, \@changes) or 0 if no fresh README found.
# $cfg_dir defaults to \$ENV{ASBRU_CFG}.
sub check {
    my $cfg_dir = shift // $ENV{ASBRU_CFG} // '';
    my $readme_file = "$cfg_dir/tmp/latest_README";

    open(my $fh, '<:encoding(UTF-8)', $readme_file) or return 0;
    my @readme;
    while (my $line = <$fh>) {
        chomp $line;
        push @readme, $line;
    }
    close $fh;

    my $version = $readme[56] // 0;
    $version =~ s/^\s+-\s+(.+):/$1/go;
    return 0 unless $version;

    my @changes = splice(@readme, 54);
    unlink $readme_file;

    return ($version, \@changes);
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Util::Readme — parse README for "what's new" popup

=head1 SYNOPSIS

    use PAC::Util::Readme;

    my ($version, $changes) = PAC::Util::Readme::check();
    if ($version) {
        # Show "what's new in $version" popup with @$changes
    }

=head1 DESCRIPTION

The asbru launcher writes a fresh copy of the project README to
C<\$CFG_DIR/tmp/latest_README> at startup. This module reads it and
extracts the version + changelog block from known line offsets.
Used by the post-upgrade "what's new" popup.

The fixed line offsets (54 = changelog start, 56 = version) are
brittle but match the upstream README format. If the README format
changes, only this one extraction needs to update.

Mechanical extraction from C<PACUtils::_checkREADME>; PACUtils retains
a 1-line goto-proxy.

=head1 PUBLIC API

=over

=item check($cfg_dir?)

Parses C<\$cfg_dir/tmp/latest_README> (defaults to C<\$ENV{ASBRU_CFG}>).
Returns C<(\$version, \\\@changes)> on success, C<0> when no fresh
README is found or version line is empty. Deletes the README file
on success (so subsequent calls return 0 until a new one is written).

=back

=head1 SEE ALSO

L<PACUtils>.

=cut
