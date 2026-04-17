package PACSshConfig;

###############################################################################
# Parse OpenSSH client config (~/.ssh/config) into a list of importable Host
# entries. Pure-Perl, no GTK / no Asbrú deps — keep it that way so it stays
# testable in isolation.
###############################################################################

use strict;
use warnings;

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

sub importable {
    my $h = shift;
    return 0 unless $h && defined $h->{alias};
    return 0 if $h->{alias} =~ /[*?]/;
    return 0 if $h->{alias} eq '';
    return 1;
}

1;
