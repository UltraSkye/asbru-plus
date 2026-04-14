#!/usr/bin/perl

use strict;
use warnings;
use utf8;
binmode STDOUT, ':utf8';
binmode STDERR, ':utf8';

if (!$ARGV[0]) {
    print STDERR "usage: perl anonymize.pl myfile.yml\n";
    exit 1;
}

exit cleanUpPersonalData($ARGV[0]) ? 0 : 1;

sub cleanUpPersonalData {
    my $file = shift;
    my $out  = 'debug.yml';

    open(my $fh_in, '<:utf8', $file)
        or die "ERROR: Cannot open '$file' for reading: $!\n";
    open(my $fh_out, '>:utf8', $out)
        or do { close $fh_in; die "ERROR: Cannot open '$out' for writing: $!\n" };

    my $C = 0;
    while (my $line = <$fh_in>) {
        my $next = 0;
        foreach my $key ('name', 'send', 'ip', 'user', 'prepend command', 'database', 'gui password', 'sudo password') {
            if ($line =~ /^[\t ]+\Q$key\E:/) {
                $line =~ s/\Q$key\E:.+/$key: 'removed'/;
                $next = 1;
            }
            last if $next;
        }
        if ($line =~ /KPX title regexp/) {
            $line =~ s/KPX title regexp:.+/KPX title regexp: ''/;
        } elsif ($line =~ /^[\t ]+(title|name):/) {
            my $p = $1;
            $C++ if $p eq 'name';
            $line =~ s/\Q$p\E:.+/$p: '$p $C'/;
        } elsif (($line =~ /^[\t ]+(global variables|remote commands|local commands|expect|local before|local after|local connected):/)
                 && ($line !~ /: \[\]/)) {
            my $global = $line =~ /global variables/ ? 1 : 0;
            my $indent = ($line =~ /^([\t ]+)/) ? $1 : '';
            print $fh_out $line;
            while (my $l = <$fh_in>) {
                if ($l =~ /^\Q$indent\E\w/) {
                    print $fh_out $l;
                    last;
                } elsif ($global) {
                    next;
                } elsif ($l =~ /description|expect|send|txt/) {
                    $l =~ s|(.+?):.+|$1: 'removed'|;
                }
                print $fh_out $l;
            }
            next;
        } elsif ($line =~ /^[\t ]+options:/) {
            $line =~ s/\/drive:.+?( |\')/\/drive: removed$1/;
            $line =~ s/ disk:.+?( |\')/ disk: removed$1/;
            $line =~ s/\/d:.+?( |\')/\/d: removed$1/;
            $line =~ s/-d .+?( |\')/-d removed$1/;
            if ($line =~ / -(D|L|R)/) {
                $line =~ s/(^[\t ]+options):.+/$1: 'removed'/;
            }
        } elsif (($line =~ /^[\t ]+proxy (ip|pass|user):/) && ($line !~ /: \'\'/)) {
            $line =~ s/(proxy.+?):.+/$1: 'removed'/;
        } elsif (($line =~ /^[\t ]+jump (config|ip|pass|user|key):/) && ($line !~ /: \'\'/)) {
            $line =~ s/(jump.+?):.+/$1: 'removed'/;
        } elsif ($line =~ /^[\t ]+description:/) {
            $line =~ s/description:.+/description: 'Description'/;
        } elsif ($line =~ /^[\t ]+public key:/) {
            $line =~ s/public key:.+/public key: 'uses public key'/;
        } elsif ($line =~ /^[\t ]+pass(word|phrase)?:/) {
            $line =~ s/pass(word|phrase)?:.+/pass$1: 'removed'/;
        } elsif ($line =~ /^[\t ]+use gui password( tray)?:/) {
            $line =~ s/use gui password( tray)?:.+/use gui password$1: \'\'/;
        } elsif ($line =~ /^[\t ]+passphrase user:/) {
            $line =~ s/passphrase user:.+/passphrase user: 'removed'/;
        }
        $line =~ s|/home/[^/]+/|/home/PATH/|g;
        my $user = $ENV{USER} // $ENV{LOGNAME} // '';
        $line =~ s|\Q$user\E|USER|g if $user ne '';
        print $fh_out $line;
    }

    # Append sanitized runtime environment
    print $fh_out "\n\n# ENV Data\n";
    my $user = $ENV{USER} // $ENV{LOGNAME} // '';
    foreach my $k (sort keys %ENV) {
        next if $k =~ /token|hostname|startup|KPXC|AUTH/i;
        my $str = $ENV{$k} // '';
        $str =~ s|\Q$user\E|USER|g if $user ne '';
        print $fh_out "#$k : $str\n";
    }
    print $fh_out "\n\n";

    close $fh_in;
    close $fh_out;

    print STDERR "Wrote anonymized output to '$out'\n";
    return 1;
}
