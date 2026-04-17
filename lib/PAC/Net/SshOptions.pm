package PAC::Net::SshOptions;

###############################################################################
# PAC::Net::SshOptions — parser/normalizer for the legacy free-form SSH
# options string used in older Ásbrú config formats.
#
# Takes a string like " -2 -X -L 8080:server:80 -o 'CompressionLevel=6'"
# and returns a normalized rebuilt string. Used during migration of
# pre-6.x configs that stored options as raw strings rather than
# structured hashes.
#
# Mechanical extraction from PACUtils::_updateSSHToIPv6. PACUtils
# retains a 1-line proxy. The function is not called by any production
# code path today; only t/16-deep-functional.t exercises it. Keeping it
# extractable lets us delete it cleanly when we're confident no
# downstream forks rely on it.
###############################################################################

use strict;
use warnings;
use utf8;

use Getopt::Long qw(GetOptionsFromString);

our $VERSION = '0.1.0';

# normalize_options($cmd_line) — see POD at end of file.
sub normalize_options {
    my $cmd_line = shift // '';

    my %hash;
    $hash{sshVersion} = 'any';
    $hash{ipVersion} = 'any';
    $hash{forwardX} = 1;
    $hash{useCompression} = 0;
    $hash{allowRemoteConnection} = 0;
    $hash{forwardAgent} = 0;
    $hash{otherOptions} = '';
    @{$hash{dynamicForward}} = ();
    @{$hash{forwardPort}} = ();
    @{$hash{remotePort}} = ();

    while ($cmd_line =~ s/\s*\-o\s+\"(.+)\"//go) {
        $hash{otherOptions} .= qq| -o "$1"|;
    }
    my @opts = split(/\s+-/, $cmd_line);
    foreach my $opt (@opts) {
        if ($opt eq '') {
            next;
        }
        $opt =~ s/\s+$//go;

        if ($opt =~ /^([1|2]$)/go) {
            $hash{sshVersion} = $1;
        }
        if ($opt =~ /^([4|6]$)/go) {
            $hash{ipVersion} = $1;
        }
        if ($opt =~ /^([X|x]$)/go) {
            $hash{forwardX} = $1 eq 'X' ? 1 : 0;
        }
        if ($opt eq 'C') {
            $hash{useCompression} = 1;
        }
        if ($opt eq 'g') {
            $hash{allowRemoteConnection} = 1;
        }
        if ($opt eq 'A') {
            $hash{forwardAgent} = 1;
        }

        while ($opt =~ /^D\s+([^\s]*:)*(\d+)$/go) {
            my %dynamic;
            ($dynamic{dynamicIP}, $dynamic{dynamicPort}) = ($1 // '', $2);
            $dynamic{dynamicIP} =~ s/:+//go;
            push(@{$hash{dynamicForward}}, \%dynamic);
        }
        while ($opt =~ /^L\s+(.+)$/go) {
            my @fields = split(':', $1);
            my %forward;
            $forward{remotePort} = pop(@fields);
            $forward{remoteIP} = pop(@fields);
            $forward{localPort} = pop(@fields);
            $forward{localIP} = pop(@fields) // '';
            push(@{$hash{forwardPort}}, \%forward);
        }
        while ($opt =~ /^R\s+(.+)$/go) {
            my @fields = split(':', $1);
            my %remote;
            $remote{remotePort} = pop(@fields);
            $remote{remoteIP} = pop(@fields);
            $remote{localPort} = pop(@fields);
            $remote{localIP} = pop(@fields) // '';
            push(@{$hash{remotePort}}, \%remote);
        }
    }

    my $txt = '';

    if ($hash{sshVersion} ne 'any') {
        $txt .= " -$hash{sshVersion}";
    }
    if ($hash{ipVersion} ne 'any') {
        $txt .= " -$hash{ipVersion}";
    }
    $txt .= ' -' . ($hash{forwardX} ? 'X' : 'x');
    if ($hash{useCompression}) {
        $txt .= ' -C';
    }
    if ($hash{allowRemoteConnection}) {
        $txt .= ' -g';
    }
    if ($hash{forwardAgent}) {
        $txt .= ' -A';
    }
    if ($hash{otherOptions}) {
        $txt .= " $hash{otherOptions}";
    }
    foreach my $dynamic (@{$hash{dynamicForward}}) {
        $txt .= ' -D ' . ($$dynamic{dynamicIP} ? "$$dynamic{dynamicIP}/" : '') . $$dynamic{dynamicPort};
    }
    foreach my $forward (@{$hash{forwardPort}}) {
        $txt .= ' -L ' . ($$forward{localIP} ? "$$forward{localIP}/" : '') . $$forward{localPort} . '/' . $$forward{remoteIP} . '/' . $$forward{remotePort};
    }
    foreach my $remote (@{$hash{remotePort}}) {
        $txt .= ' -R ' . ($$remote{localIP} ? "$$remote{localIP}/" : '') . $$remote{localPort} . '/' . $$remote{remoteIP} . '/' . $$remote{remotePort};
    }

    return $txt;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Net::SshOptions — parser/normalizer for legacy SSH options strings

=head1 SYNOPSIS

    use PAC::Net::SshOptions;

    my $clean = PAC::Net::SshOptions::normalize_options(' -2 -X -C');
    # → " -2 -X -C" (canonical form)

=head1 DESCRIPTION

Parses the legacy free-form SSH options string used in older Ásbrú
config formats and rebuilds it in a canonical, validated form. Used
during config migration to extract structured per-flag values from a
raw command-line string.

Mechanical extraction of C<PACUtils::_updateSSHToIPv6> (the original
name was misleading — it normalizes ALL ssh options, not just IPv6).
PACUtils retains a 1-line proxy under the legacy name.

=head1 PUBLIC API

=over

=item normalize_options($cmd_line)

Parses C<$cmd_line> via L<Getopt::Long> (bundling mode) and rebuilds
it as a canonical option string. Returns the rebuilt string.

The expected input is a leading-space + flags layout (the legacy
config format), e.g. C<' -2 -X -L 8080:host:22'>. Unrecognized flags
are silently dropped. Returns the empty string on undef input.

=back

=head1 SEE ALSO

L<PAC::Net::SshConfig>, L<Getopt::Long>.

=cut
