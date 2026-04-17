package PAC::Config::TmpSessions;

###############################################################################
# PAC::Config::TmpSessions — extract / restore temporary session entries
# from the asbru config.
#
# Temporary sessions are environment entries whose UUID starts with
# 'HASH', '_tmp_', or 'pacshell_PID' — these are runtime placeholders
# that should not be persisted to disk during config save. The pair
# of helpers here lets the save flow strip them out before write and
# put them back afterwards.
#
# Mechanical extraction from PACUtils::_cfgGetTmpSessions and
# _cfgAddSessions. PACUtils retains 1-line goto-proxies.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# extract($cfg) — returns a hash of temporary session entries pulled
# from $cfg->{environments}, keyed by UUID. Does NOT modify $cfg.
sub extract {
    my $cfg = shift;
    my %tmp;
    foreach my $uuid (keys %{$$cfg{'environments'}}) {
        if ($uuid =~ /^(HASH|_tmp_|pacshell_PID)/o) {
            $tmp{$uuid} = $$cfg{'environments'}{$uuid};
        }
    }
    return %tmp;
}

# restore($cfg, $tmp_hashref) — re-inserts the previously-extracted
# temporary sessions back into $cfg->{environments}. Mutates $cfg.
sub restore {
    my ($cfg, $tmp) = @_;
    foreach my $uuid (keys %{$tmp}) {
        $$cfg{'environments'}{$uuid} = $tmp->{$uuid};
    }
    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Config::TmpSessions — strip / restore temp session entries

=head1 SYNOPSIS

    use PAC::Config::TmpSessions;

    my %tmp = PAC::Config::TmpSessions::extract($cfg);
    # ... save $cfg without the temporary entries ...
    PAC::Config::TmpSessions::restore($cfg, \%tmp);

=head1 DESCRIPTION

Temporary session entries (UUID prefix C<HASH>, C<_tmp_>, or
C<pacshell_PID>) are runtime placeholders that should not be
persisted. The save flow uses these helpers to strip them out
before writing the config to disk and put them back afterward.

Mechanical extraction from C<PACUtils::_cfgGetTmpSessions> and
C<_cfgAddSessions>. PACUtils retains 1-line goto-proxies under
the legacy names.

=head1 PUBLIC API

=over

=item extract($cfg)

Returns a hash of temporary session entries (keyed by UUID),
WITHOUT modifying C<$cfg>.

=item restore($cfg, $tmp_hashref)

Re-inserts the previously-extracted temporary sessions back into
C<$cfg-E<gt>{environments}>. Mutates C<$cfg>.

=back

=head1 SEE ALSO

L<PACUtils>.

=cut
