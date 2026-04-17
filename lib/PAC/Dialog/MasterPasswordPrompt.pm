package PAC::Dialog::MasterPasswordPrompt;

###############################################################################
# PAC::Dialog::MasterPasswordPrompt — first-run prompt offering to set
# a master password for the credential vault.
#
# When the configuration has no master_password_verifier ("true first
# run"), this prompt warns the user that the default cipher key is
# public and offers to set one. The decision is persisted (even if
# declined) by writing an empty string into master_password_verifier
# so the warning never reappears.
#
# Mechanical extraction from PACMain::_promptSetMasterPassword.
# PACMain retains a 1-line proxy.
###############################################################################

use strict;
use warnings;
use utf8;

use Storable qw(nstore);

our $VERSION = '0.1.0';

# prompt($self) — show the warning and (if accepted) capture +
# confirm a new master password, switching the active cipher to it.
# No-op when master_password_verifier is already defined.
sub prompt {
    my $self = shift;

    # Only prompt when verifier is undefined (true first run). Empty string
    # means the user has been asked before and declined — do not re-ask.
    return if defined $$self{_CFG}{'defaults'}{'master_password_verifier'};

    my $answ = PACUtils::_wConfirm(undef,
        "<b>Security Warning — Master Password Required</b>\n\n"
        . "Your connection passwords are encrypted with a "
        . "<b>default key that is public</b>.\n"
        . "Without a master password, anyone with access to your "
        . "config files\ncan decrypt all stored credentials.\n\n"
        . "<b>Setting a master password is strongly recommended.</b>\n\n"
        . "Set a master password now?"
    );

    if ($answ) {
        my $new_pass = PACUtils::_wEnterValue(
            undef, '<b>Set Master Password</b>',
            'Enter a new master password:',
            undef, 0, 'asbru-protected',
        );
        if (defined $new_pass && $new_pass ne '') {
            my $confirm = PACUtils::_wEnterValue(
                undef, '<b>Confirm Master Password</b>',
                'Re-enter your master password:',
                undef, 0, 'asbru-protected',
            );
            if (defined $confirm && $confirm eq $new_pass) {
                # cfg is already plaintext (decrypted by _readConfiguration).
                # Switch the active cipher to the new master password — the
                # _cipherCFG call below in the persistence block will encrypt
                # the now-plaintext fields with this new cipher.
                PACUtils::_initMasterCipher($new_pass);
                $$self{_CFG}{'defaults'}{'master_password_verifier'}
                    = PACUtils::_createMasterVerifier($new_pass);
                print STDERR
                    "INFO: Master password set. All credentials re-encrypted.\n";
            } else {
                PACUtils::_wMessage(undef,
                    'Passwords did not match. Skipping master password setup.');
                $$self{_CFG}{'defaults'}{'master_password_verifier'} = '';
            }
        } else {
            $$self{_CFG}{'defaults'}{'master_password_verifier'} = '';
        }
    } else {
        # User declined — mark as offered so we don't ask again.
        $$self{_CFG}{'defaults'}{'master_password_verifier'} = '';
    }

    # Persist the decision so the warning does not reappear next launch.
    # We CANNOT call _saveConfiguration here because it touches GUI state
    # (_saveTreeExpanded, statistics->saveStats) that doesn't exist yet.
    # Instead do a minimal nstore+HMAC of the encrypted cfg.
    eval {
        my $cfg = $$self{_CFG};
        # Re-encrypt password fields with the (possibly new) active cipher
        PACUtils::_cipherCFG($cfg);
        nstore($cfg, $PACMain::CFG_FILE_NFREEZE) or die "nstore failed: $!\n";
        PAC::Crypto::HMAC::write_for($PACMain::CFG_FILE_NFREEZE);
        # Restore plaintext for the rest of startup
        PACUtils::_decipherCFG($cfg);
    };
    if ($@) {
        print STDERR
            "WARN: Could not persist master_password_verifier state: $@\n";
    }
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Dialog::MasterPasswordPrompt — first-run master-password offer

=head1 SYNOPSIS

    use PAC::Dialog::MasterPasswordPrompt;

    PAC::Dialog::MasterPasswordPrompt::prompt($self);

=head1 DESCRIPTION

On true first run (when C<master_password_verifier> is C<undef>),
warn the user that the default cipher key is public and offer to
set a master password. The decision is persisted either way:

=over

=item *

If the user accepts and confirms a password, that password becomes
the active master cipher and a verifier is generated and stored.

=item *

If the user declines, an empty C<master_password_verifier> is
written so the prompt does not reappear.

=back

The persistence is a minimal C<nstore + HMAC sidecar> (no full
save pipeline) because GUI state used by L<PAC::Config::Save>
does not yet exist when this prompt runs.

Mechanical extraction from C<PACMain::_promptSetMasterPassword>.
PACMain retains a 1-line proxy.

=head1 PUBLIC API

=over

=item prompt($self)

Show the warning + capture + confirm flow described above. No-op
when C<\$self-E<gt>{_CFG}{defaults}{master_password_verifier}> is
already defined (including the empty string).

=back

=head1 SEE ALSO

L<PAC::Vault>, L<PAC::Crypto::HMAC>, L<PAC::Config::Save>.

=cut
