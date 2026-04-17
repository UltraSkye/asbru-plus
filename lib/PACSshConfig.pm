package PACSshConfig;

###############################################################################
# COMPATIBILITY SHIM. The real implementation lives at
# lib/PAC/Net/SshConfig.pm (PAC::Net::SshConfig). This file is kept so
# existing `use PACSshConfig;` callers continue to work; new code MUST
# `use PAC::Net::SshConfig;`.
#
# Will be removed in a future release once all callers migrate.
###############################################################################

use strict;
use warnings;
use utf8;

use PAC::Net::SshConfig;

our $VERSION = '0.2.0';

sub parse      { goto &PAC::Net::SshConfig::parse; }
sub importable { goto &PAC::Net::SshConfig::importable; }

1;

__END__

=encoding utf8

=head1 NAME

PACSshConfig — backward-compat shim for L<PAC::Net::SshConfig>

=head1 STATUS

Deprecated. New code MUST use L<PAC::Net::SshConfig>.

=head1 PUBLIC API

=over

=item parse($path)

Forwards to L<PAC::Net::SshConfig/parse>.

=item importable($host)

Forwards to L<PAC::Net::SshConfig/importable>.

=back

=head1 SEE ALSO

L<PAC::Net::SshConfig>.

=cut
