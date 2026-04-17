package PAC::Logger;

###############################################################################
# PAC::Logger — leveled diagnostics for asbru-plus.
#
# Replaces the ad-hoc `print STDERR "WARN: ..."` pattern scattered across
# 10 files (~75 callsites) with a single API that:
#   - filters by level (FATAL > ERROR > WARN > INFO > DEBUG)
#   - keeps STDERR output 100% backward-compatible (same prefix + format)
#   - optionally writes to ~/.config/asbru/logs/asbru-plus.log
#   - is async-signal safe (no buffering, single write())
#
# Migration policy:
#   - All NEW code MUST use PAC::Logger::warn / error / info / debug.
#   - Legacy `print STDERR "WARN: ..."` callsites stay as-is — they produce
#     identical output. Migrate opportunistically; not a blocker.
###############################################################################

use strict;
use warnings;
use utf8;

use Carp ();
use Fcntl qw(:flock O_WRONLY O_APPEND O_CREAT);

our $VERSION = '0.1.0';

# Numeric levels (lower = more severe). Set by env var ASBRU_LOG_LEVEL or
# at runtime via set_level().
use constant {
    LVL_FATAL => 0,
    LVL_ERROR => 1,
    LVL_WARN  => 2,
    LVL_INFO  => 3,
    LVL_DEBUG => 4,
};

my %NAME_TO_LVL = (
    FATAL => LVL_FATAL,
    ERROR => LVL_ERROR,
    WARN  => LVL_WARN,
    INFO  => LVL_INFO,
    DEBUG => LVL_DEBUG,
);

# Default to INFO. Override via $ENV{ASBRU_LOG_LEVEL}=DEBUG (or WARN/etc.)
# or programmatically via set_level('DEBUG').
my $CURRENT_LEVEL = LVL_INFO;
if (defined $ENV{ASBRU_LOG_LEVEL}
    && exists $NAME_TO_LVL{uc $ENV{ASBRU_LOG_LEVEL}}) {
    $CURRENT_LEVEL = $NAME_TO_LVL{uc $ENV{ASBRU_LOG_LEVEL}};
}

# Optional file sink. Set via set_file($path) or $ENV{ASBRU_LOG_FILE}=path.
my $LOG_FILE_PATH;
my $LOG_FILE_FH;
if ($ENV{ASBRU_LOG_FILE}) {
    set_file($ENV{ASBRU_LOG_FILE});
}

#-------------------------------------------------------------------------
# Public configuration
#-------------------------------------------------------------------------

sub set_level {
    my $level = shift;
    if (!defined $level) {
        Carp::croak('PAC::Logger::set_level: level required');
    }
    if ($level =~ /^\d+$/) {
        $CURRENT_LEVEL = $level;
    } elsif (exists $NAME_TO_LVL{uc $level}) {
        $CURRENT_LEVEL = $NAME_TO_LVL{uc $level};
    } else {
        Carp::croak("PAC::Logger::set_level: unknown level '$level'");
    }
    return $CURRENT_LEVEL;
}

sub current_level { return $CURRENT_LEVEL; }

sub set_file {
    my $path = shift;
    if (!defined $path || $path eq '') {
        if ($LOG_FILE_FH) { close $LOG_FILE_FH; $LOG_FILE_FH = undef; }
        $LOG_FILE_PATH = undef;
        return;
    }
    # SECURITY: log may contain sensitive context. Tighten umask to
    # 0077 around the create so a brand-new log file is mode 0600
    # atomically — the trailing chmod is now belt-and-suspenders for
    # the case where the file already existed at wider perms (chmod
    # under append-open does not by itself widen an already-tight
    # file). Without the umask wrap, a process killed between open
    # and chmod could leave a brand-new 0644 log on disk that
    # subsequent appends would silently extend.
    my $old_umask = umask(0077);
    open(my $fh, '>>', $path)
        or do { umask($old_umask); Carp::croak("PAC::Logger::set_file: cannot open $path: $!"); };
    umask($old_umask);
    chmod 0600, $path;
    $fh->autoflush(1);
    if ($LOG_FILE_FH) { close $LOG_FILE_FH; }
    $LOG_FILE_FH   = $fh;
    $LOG_FILE_PATH = $path;
    return $path;
}

sub log_file { return $LOG_FILE_PATH; }

#-------------------------------------------------------------------------
# Public emitters
#-------------------------------------------------------------------------

sub fatal { _emit(LVL_FATAL, 'FATAL', @_); }
sub error { _emit(LVL_ERROR, 'ERROR', @_); }
sub warn  { _emit(LVL_WARN,  'WARN',  @_); }
sub info  { _emit(LVL_INFO,  'INFO',  @_); }
sub debug { _emit(LVL_DEBUG, 'DEBUG', @_); }

#-------------------------------------------------------------------------
# Internal
#-------------------------------------------------------------------------

sub _emit {
    my ($lvl, $tag, @msg) = @_;
    return if $lvl > $CURRENT_LEVEL;

    my $msg = join('', @msg);
    chomp $msg;
    my $line = "$tag: $msg\n";

    # STDERR is line-buffered + async-signal safe in Perl by default.
    print STDERR $line;

    # Optional file sink.
    if ($LOG_FILE_FH) {
        my @t = localtime;
        my $stamp = sprintf('%04d-%02d-%02dT%02d:%02d:%02d',
            $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0]);
        eval {
            flock($LOG_FILE_FH, LOCK_EX);
            print {$LOG_FILE_FH} "$stamp $tag: $msg\n";
            flock($LOG_FILE_FH, LOCK_UN);
        };
        # Don't recurse if file write fails — just drop to stderr.
        if ($@) {
            print STDERR "PAC::Logger: file sink write failed: $@";
        }
    }
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Logger — leveled diagnostics for asbru-plus

=head1 SYNOPSIS

    use PAC::Logger;

    PAC::Logger::error("vault unlock failed: $err");
    PAC::Logger::warn("config key '$key' is deprecated");
    PAC::Logger::info("loaded $n connections from $path");
    PAC::Logger::debug("cipher rotation pass: $pass");

    # Configure at runtime (or via env)
    PAC::Logger::set_level('DEBUG');               # default INFO
    PAC::Logger::set_file("$ENV{HOME}/.config/asbru/logs/asbru.log");

=head1 DESCRIPTION

Replaces the C<print STDERR "WARN: ..."> pattern scattered across the
codebase (~75 callsites in 10 files) with a single API that filters by
level and optionally writes to a log file.

The STDERR output is byte-identical to the legacy pattern — same
prefix, same format. New code uses PAC::Logger; legacy callsites can
migrate at any pace without changing observable behavior.

=head1 CONFIGURATION

=over

=item set_level($level)

Sets the minimum severity level. Accepts either a level name
(C<FATAL>, C<ERROR>, C<WARN>, C<INFO>, C<DEBUG>) or its numeric
constant (0–4, lower = more severe). Returns the new numeric level.

Defaults to C<INFO>. Can also be set via C<$ENV{ASBRU_LOG_LEVEL}>.

=item current_level

Returns the active numeric level.

=item set_file($path)

Enables a file sink at C<$path>. Pass undef or empty string to
disable. The file is opened in append mode with C<chmod 0600> (logs
may contain sensitive context). Each line is timestamped
(C<YYYY-MM-DDTHH:MM:SS>) and locked with C<flock(LOCK_EX)>.

=item log_file

Returns the active file sink path, or C<undef>.

=back

=head1 EMITTERS

=over

=item fatal(@parts)

=item error(@parts)

=item warn(@parts)

=item info(@parts)

=item debug(@parts)

Each emitter joins its arguments with no separator, chomps a trailing
newline, prepends C<TAG: >, and prints to STDERR. If a file sink is
configured, also writes a timestamped line to it. Below the active
level → no output.

=back

=head1 ENVIRONMENT

=over

=item ASBRU_LOG_LEVEL

Sets the initial level. One of FATAL/ERROR/WARN/INFO/DEBUG (case
insensitive).

=item ASBRU_LOG_FILE

Sets the initial file sink path.

=back

=head1 SEE ALSO

L<perlsec/Asynchronous-signal handling> for the safety properties of
C<print STDERR>.

=cut
