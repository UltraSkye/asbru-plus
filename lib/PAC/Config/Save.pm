package PAC::Config::Save;

###############################################################################
# PAC::Config::Save — persist the in-memory configuration to disk.
#
# Wraps the full save pipeline:
#   1. purge unused/missing screenshots
#   2. snapshot temporary sessions (so they survive sanity-check eviction)
#   3. cfgSanityCheck + cipherCFG (passwords are encrypted on disk)
#   4. write the primary $CFG_FILE_NFREEZE under an exclusive flock
#      (with an O_NOFOLLOW lock-file open + symlink refusal — see
#      SECURITY.md for the rationale)
#   5. write the optional $R_CFG_FILE replica
#   6. emit the HMAC sidecars via PAC::Crypto::HMAC
#   7. restore plaintext passwords + temporary sessions in memory
#   8. save tree-expanded state + statistics
#   9. flip the "config changed" indicator (unless $normal == 0)
#
# Mechanical extraction from PACMain::_saveConfiguration. PACMain
# retains a 1-line proxy.
###############################################################################

use strict;
use warnings;
use utf8;

use Fcntl qw(:flock);
use Storable qw(nstore);

our $VERSION = '0.1.0';

# save($self, $cfg=$self->{_CFG}, $normal=1) — write $cfg to disk.
# Returns the primary nfreeze path on success, 1 in read-only mode,
# 0 if a symlinked config file blocked the write.
sub save {
    my $self   = shift;
    my $cfg    = shift // $$self{_CFG};
    my $normal = shift // 1;

    my %tmp_sessions;

    # Purge screenshots that no longer have a referencing connection,
    # or whose file has gone missing on disk.
    PACUtils::_purgeUnusedOrMissingScreenshots($cfg);

    # Snapshot temporary sessions before sanity-check evicts them
    # (we don't want those persisted, but we need them in memory).
    %tmp_sessions = PACUtils::_cfgGetTmpSessions($cfg);

    # Sanity check + drop temporary sessions.
    PACUtils::_cfgSanityCheck($cfg);

    # Encrypt password fields so they don't hit disk in plaintext.
    PACUtils::_cipherCFG($cfg);

    # Read-only instance: don't actually write anything.
    return 1 if $$self{_READONLY};

    my $primary = $PACMain::CFG_FILE_NFREEZE;

    # SECURITY: refuse symlinked config files / lock files — those would
    # let an attacker redirect our writes to /etc/passwd or similar.
    if (-l $primary) {
        PACUtils::_wMessage(
            $$self{_GUI}{main},
            "ERROR: '$primary' is a symlink — refusing to save",
        );
        return 0;
    }

    my $lock_path = "$primary.lock";
    unlink $lock_path if -l $lock_path;   # drop stale symlink before O_NOFOLLOW open
    require Fcntl;
    my $lock_flags = Fcntl::O_WRONLY() | Fcntl::O_CREAT() | Fcntl::O_TRUNC();
    $lock_flags |= Fcntl::O_NOFOLLOW() if defined &Fcntl::O_NOFOLLOW;

    if (sysopen(my $lock_fh, $lock_path, $lock_flags, 0600)) {
        flock($lock_fh, LOCK_EX);
        nstore($cfg, $primary)
            or PACUtils::_wMessage(
                $$self{_GUI}{main},
                "ERROR: Could not save config file '$primary':\n\n$!",
            );
        PAC::Crypto::HMAC::write_for($primary);
        flock($lock_fh, LOCK_UN);
        close $lock_fh;
    } else {
        # Lock-file open refused (e.g. directory permissions or symlink
        # caught by O_NOFOLLOW): write the config anyway, no flock.
        nstore($cfg, $primary)
            or PACUtils::_wMessage(
                $$self{_GUI}{main},
                "ERROR: Could not save config file '$primary':\n\n$!",
            );
        PAC::Crypto::HMAC::write_for($primary);
    }

    # Optional replica path (e.g. shared/synced config dir).
    if ($PACMain::R_CFG_FILE) {
        nstore($cfg, $PACMain::R_CFG_FILE)
            or PACUtils::_wMessage(
                $$self{_GUI}{main},
                "ERROR: Could not save config file '$PACMain::R_CFG_FILE':\n\n$!\n\n"
                . "Local copy saved at '$primary'",
            );
        PAC::Crypto::HMAC::write_for($PACMain::R_CFG_FILE);
    }

    # Restore plaintext passwords + temporary sessions in memory.
    PACUtils::_decipherCFG($cfg);
    PACUtils::_cfgAddSessions($cfg, \%tmp_sessions);

    # Persist tree-expanded state + statistics counters.
    $self->_saveTreeExpanded();
    $$self{_GUI}{statistics}->saveStats();

    $normal and $self->_setCFGChanged(0);

    return $primary;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Config::Save — persist the in-memory configuration to disk

=head1 SYNOPSIS

    use PAC::Config::Save;

    PAC::Config::Save::save($self);                 # use $self->{_CFG}
    PAC::Config::Save::save($self, \%cfg);          # explicit cfg
    PAC::Config::Save::save($self, \%cfg, 0);       # quiet — don't flip
                                                    # the "changed" indicator

=head1 DESCRIPTION

Wraps the full save pipeline: screenshot purge, temporary-session
snapshot, sanity check, password encryption, symlink-refusal +
flocked write of the primary nfreeze + optional replica, HMAC
sidecar emission, in-memory restoration of plaintext passwords +
temporary sessions, tree-expanded persistence, statistics save,
"config changed" reset.

The symlink refusal + C<O_NOFOLLOW> lock-file open are
defense-in-depth — see C<SECURITY.md>.

Mechanical extraction from C<PACMain::_saveConfiguration>. PACMain
retains a 1-line proxy.

=head1 PUBLIC API

=over

=item save($self, $cfg=$self->{_CFG}, $normal=1)

Persist C<$cfg>. Returns:

=over

=item *

The primary nfreeze path on success.

=item *

C<1> in read-only mode (no-op).

=item *

C<0> when a symlinked primary config file blocked the write.

=back

When C<$normal> is true (default), calls C<$self-E<gt>_setCFGChanged(0)>
at the end to flip the "config changed" indicator off.

=back

=head1 SECURITY

=over

=item *

Refuses to overwrite C<$CFG_FILE_NFREEZE> when it is a symlink.

=item *

Opens the C<.lock> file with C<O_NOFOLLOW> when available (drops a
stale symlink first) so an attacker cannot pre-create the lock
path as a symlink to redirect writes.

=item *

Encrypts password fields via L<PAC::Crypto::Cipher> before they
hit disk; emits HMAC sidecars via L<PAC::Crypto::HMAC>.

=back

=head1 SEE ALSO

L<PAC::Crypto::HMAC>, L<PAC::Crypto::Cipher>, L<PAC::Tree::State>,
L<SECURITY.md>.

=cut
