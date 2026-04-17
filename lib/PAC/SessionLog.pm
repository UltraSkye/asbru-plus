package PAC::SessionLog;

###############################################################################
# PAC::SessionLog — helpers for managing per-session log files and
# the screenshots cache.
#
# Bundles four related helpers extracted from PACUtils:
#   - delete_oldest($uuid, $folder, $max)
#   - replace_bad_chars($string)
#   - remove_escape_seqs($string)
#   - purge_screenshots($cfg)
#
# PACUtils retains 1-line proxies under the legacy underscored names.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# Helper to recover CFG_DIR (was a 'my' lexical inside PACUtils).
sub _cfg_dir { return $ENV{ASBRU_CFG} // ''; }

sub delete_oldest {
    my $uuid = shift;
    my $folder = shift;
    my $max = shift;

    # If MAX is 0, then keep ALL the logs.
    if (!$max) {
        return 1;
    }

    opendir(my $F, $folder) or die "ERROR: Could not open folder '$folder' for reading: $!\n";

    my @total;
    foreach my $file (readdir $F) {
        if ($file !~ /^PAC_\[(.+)_Name_(.+)\]_\[(\d{8})_(\d{6})\]\.txt$/g) {
            next;
        }
        my ($fenv, $fconn, $fdate, $ftime) = ($1, $2, $3, $4);
        push(@total, "$folder/$file");
    }

    close $F;

    if (scalar(@total) lt $max) {
        return 1;
    }

    my $i = 0;
    foreach my $file (sort {$a cmp $b} @total) {
        unlink $file or die "ERROR: Could not delete oldest log file '$file': $!\n";
        if ((scalar(@total) - $max) <= $i++) {
            last;
        }
    }

    return 1;
}

sub replace_bad_chars {
    my $string = shift // '';

    $string =~ s/\x0/'NUL (null)'/go;
    $string =~ s/\x1/'SOH(start of heading)'/go;
    $string =~ s/\x2/'STX (start of text)'/go;
    $string =~ s/\x3/'ETX (end of text)'/go;
    $string =~ s/\x4/'EOT (end of trans.)'/go;
    $string =~ s/\x5/'ENQ (enquiry)'/go;
    $string =~ s/\x6/'ACK (acknowledge)'/go;
    $string =~ s/\x7/'BEL (bell)'/go;
    $string =~ s/\x8/'BS (backspace)'/go;
    $string =~ s/\x9/'AB (horizontal tab)'/go;
    $string =~ s/\xA/'LF (NL New Line)'/go;
    $string =~ s/\xB/'VT (vertical tab)'/go;
    $string =~ s/\xC/'FF (NP new page)'/go;
    $string =~ s/\xD/'CR (carriage return)'/go;
    $string =~ s/\xE/'SO (shift out)'/go;
    $string =~ s/\xF/'SI (shift in)'/go;
    $string =~ s/\x10/'DLE (data link escape)'/go;
    $string =~ s/\x11/'DC1 (device control 1)'/go;
    $string =~ s/\x12/'DC2 (device control 2)'/go;
    $string =~ s/\x13/'DC3 (device control 3)'/go;
    $string =~ s/\x14/'DC4 (device control 4)'/go;
    $string =~ s/\x15/'NAK (negative acknow.)'/go;
    $string =~ s/\x16/'SYN (synchronous idle)'/go;
    $string =~ s/\x17/'ETB (end of trans.blow)'/go;
    $string =~ s/\x18/'CAN (cancel)'/go;
    $string =~ s/\x19/'EM (end of medium)'/go;
    $string =~ s/\x1A/'SUB (substitute)'/go;
    $string =~ s/\x1B/'ESC (escape)'/go;
    $string =~ s/\x1C/'FS (file separator)'/go;
    $string =~ s/\x1D/'GS (group separator)'/go;
    $string =~ s/\x1E/'RS (record separator)'/go;
    $string =~ s/\x1F/'US (unit separator)'/go;
    $string =~ s/\x7f/\(BACKSPACE\)/go;

    return $string;
}

sub remove_escape_seqs {
    my $string = shift // '';

    $string =~ s/\x07/\x07\n/g;
    $string =~ s/\x1B[=>]//g;
    $string =~ s/\e\[[0-9;]*[a-zA-Z]%?//g;
    $string =~ s/\e\[[0-9;]*m(?:\e\[K)?//g;
    $string =~ s/\x1B\]1.+?\x07\n?//g;
    $string =~ s/(\x1B|\x08|\x07)(\[w|=|\(B)?//g;
    $string =~ s/\[\?\d+\w{1,2}//g;
    $string =~ s/\]\d;//g;

    return $string;
}

sub purge_screenshots {
    my $cfg = shift;

    my %screenshots;

    foreach my $uuid (keys %{$$cfg{'environments'}}) {
        my $i = 0;
        foreach my $screenshot (@{$$cfg{'environments'}{$uuid}{'screenshots'}}) {
            if (! -f $screenshot) {
                splice(@{$$cfg{'environments'}{$uuid}{'screenshots'}}, $i, 1);
            } else {
                ++$i;
                $screenshots{$screenshot} = 1;
            }
        }
    }

    opendir(my $dir, "_cfg_dir()/screenshots") or die "ERROR: Could not open dir '_cfg_dir()/screenshots' for reading: $!\n";
    while (my $file = readdir($dir)) {
        if ($file =~ /^\.|\.\.$/go) {
            next;
        }
        defined $screenshots{"_cfg_dir()/screenshots/$file"} or unlink "_cfg_dir()/screenshots/$file";
    }
    closedir $dir;

    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::SessionLog — per-session log file + screenshot cache helpers

=head1 SYNOPSIS

    use PAC::SessionLog;

    PAC::SessionLog::delete_oldest($uuid, $folder, $max);
    my $clean = PAC::SessionLog::replace_bad_chars($raw);
    my $no_ansi = PAC::SessionLog::remove_escape_seqs($vte_output);
    PAC::SessionLog::purge_screenshots($cfg);

=head1 DESCRIPTION

Bundles four log-and-screenshot helpers that previously lived in
PACUtils. Each is mechanically identical to its predecessor; PACUtils
retains 1-line goto-proxies so existing call sites work unchanged.

=head1 PUBLIC API

=over

=item delete_oldest($uuid, $folder, $max)

Trims the per-uuid session log directory to at most C<$max> files,
deleting the oldest first. Pass C<$max=0> to keep all logs.

=item replace_bad_chars($string)

Replaces ASCII control characters (0x00..0x1F + 0x7F) with their
human-readable mnemonic (e.g. C<\x07> → "BEL (bell)"). Used before
displaying log content in the UI.

=item remove_escape_seqs($string)

Strips ANSI/VT100 escape sequences (cursor moves, color, title) from
a captured terminal stream. Used when sanitizing logs before
storage / display.

=item purge_screenshots($cfg)

Walks every connection's screenshots list and removes references to
files that no longer exist on disk; conversely, removes any orphaned
files in C<$ASBRU_CFG/screenshots> not referenced by any connection.

=back

=head1 INTERNAL

=over

=item _cfg_dir

Returns C<$ENV{ASBRU_CFG}>. Replaces the legacy module-level
C<my $CFG_DIR> lexical from PACUtils.

=back

=head1 SEE ALSO

L<PACUtils>, L<PACTerminal>.

=cut
