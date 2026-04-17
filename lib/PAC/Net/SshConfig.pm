package PAC::Net::SshConfig;

###############################################################################
# PAC::Net::SshConfig — parse OpenSSH client config (~/.ssh/config) into a
# list of importable Host entries.
#
# Pure-Perl, no GTK / no Asbrú deps — keep it that way so it stays
# trivially testable in isolation.
#
# Used by the "Import from ~/.ssh/config" menu entry in PACMain.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.2.0';

#-------------------------------------------------------------------------
# Public API
#-------------------------------------------------------------------------

# parse($path) -> arrayref of { alias, hostname, port, user, identity_file }
# Skips wildcard hosts (Host * / *.example.com), Match blocks, Include lines.
sub parse {
    my $file = shift;
    open(my $fh, '<', $file) or return [];
    my @hosts;
    my $current;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        next if $line eq '' || $line =~ /^#/;
        if ($line =~ /^Host\s+(.+)$/i) {
            push @hosts, $current if $current && importable($current);
            my @aliases = split /\s+/, $1;
            $current = { alias => $aliases[0] };
        } elsif ($line =~ /^Match\b/i) {
            push @hosts, $current if $current && importable($current);
            $current = undef;
        } elsif ($line =~ /^Include\b/i) {
            next;
        } elsif ($current) {
            if ($line =~ /^HostName\s+(.+)$/i) {
                $current->{hostname} = $1;
            } elsif ($line =~ /^Port\s+(\d+)/i) {
                $current->{port} = $1;
            } elsif ($line =~ /^User\s+(.+)$/i) {
                $current->{user} = $1;
            } elsif ($line =~ /^IdentityFile\s+(.+)$/i) {
                (my $key = $1) =~ s{^~}{$ENV{HOME} // '~'}e;
                $current->{identity_file} = $key;
            }
        }
    }
    push @hosts, $current if $current && importable($current);
    close $fh;
    return \@hosts;
}

# importable($host) -> 1 if host is a valid importable entry
sub importable {
    my $h = shift;
    return 0 unless $h && defined $h->{alias};
    return 0 if $h->{alias} =~ /[*?]/;
    return 0 if $h->{alias} eq '';
    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Net::SshConfig — parse OpenSSH client config for bulk import

=head1 SYNOPSIS

    use PAC::Net::SshConfig;

    my $hosts = PAC::Net::SshConfig::parse("$ENV{HOME}/.ssh/config");
    for my $h (@$hosts) {
        printf "%-20s %s:%d as %s\n",
            $h->{alias}, $h->{hostname} // '?', $h->{port} // 22,
            $h->{user} // '?';
    }

=head1 DESCRIPTION

Pure-Perl SSH client config parser used by the C<Import from
~/.ssh/config> menu entry. No Gtk, no network, no asbru internal
state — kept small and isolated so it stays trivially testable.

=head1 PUBLIC API

=over

=item parse($path)

Returns an arrayref of importable host entries, each a hash with keys
C<alias>, C<hostname>, C<port>, C<user>, C<identity_file>. Returns an
empty arrayref if the file cannot be opened.

Skipped: wildcard hosts (C<Host *>), C<Match> blocks, C<Include>
directives. For C<Host alias1 alias2>, only the first alias becomes
the importable entry. Tilde in C<IdentityFile> is expanded against
C<$ENV{HOME}>.

=item importable($host)

Returns true iff C<$host> is a valid importable entry: has a non-empty
C<alias> with no C<*> or C<?> wildcards.

=back

=head1 HISTORY

Originally lived at C<lib/PACSshConfig.pm> as a transitional
flat-namespace name. Migrated to C<lib/PAC/Net/SshConfig.pm> in
v6.5.x. The old name remains as a compat shim that delegates here so
existing code keeps working.

=head1 SEE ALSO

L<ssh_config(5)>.

=cut
