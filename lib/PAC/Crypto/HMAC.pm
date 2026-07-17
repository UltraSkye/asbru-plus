package PAC::Crypto::HMAC;

###############################################################################
# PAC::Crypto::HMAC — config-integrity functions extracted from PACMain.pm.
#
# Three responsibilities:
#   1. Derive a per-installation HMAC key from the on-disk salt
#   2. Compute and persist HMAC sidecars next to config files (mode 0600,
#      O_NOFOLLOW where supported, anti-symlink-traversal hardening)
#   3. Verify HMAC sidecars at load time, with a constant-time compare
#
# Public API:
#   PAC::Crypto::HMAC::init({ cfg_dir => $dir })  — derive HMAC key
#   PAC::Crypto::HMAC::write_for($path)           — write $path.hmac sidecar
#   PAC::Crypto::HMAC::verify_for($path)          — 1=valid, 0=tampered
#   PAC::Crypto::HMAC::ct_eq($a, $b)              — constant-time compare
###############################################################################

use strict;
use warnings;
use utf8;

use Carp qw(croak);
use Digest::SHA qw(hmac_sha256_hex);
use Fcntl qw(O_WRONLY O_CREAT O_TRUNC);
use Storable qw(retrieve);

our $VERSION = '0.1.0';

#-------------------------------------------------------------------------
# Module state
#-------------------------------------------------------------------------

my $HMAC_KEY;

#-------------------------------------------------------------------------
# Initialization
#-------------------------------------------------------------------------

# init(\%opts) — derive the HMAC key from the on-disk salt at $cfg_dir/.salt.
# Falls back to a static key if salt file unavailable. Idempotent.
sub init {
    my %opts = @_ ? %{$_[0]} : ();
    my $cfg_dir = $opts{cfg_dir} // $ENV{ASBRU_CFG} // '';

    my $derived;
    if ($cfg_dir ne '') {
        my $salt_file = "$cfg_dir/.salt";
        if (-f $salt_file && open(my $fh, '<:raw', $salt_file)) {
            my $salt;
            read($fh, $salt, 16);
            close $fh;
            if (defined $salt && length($salt) >= 8) {
                $derived = hmac_sha256_hex('asbru-config-integrity-v1', $salt);
            }
        }
    }
    $HMAC_KEY = $derived // 'asbru-config-integrity-v1';
    return 1;
}

# key — returns the active HMAC key (debug / testing).
sub key {
    init() unless defined $HMAC_KEY;
    return $HMAC_KEY;
}

#-------------------------------------------------------------------------
# Public API
#-------------------------------------------------------------------------

# write_for($config_path) — compute HMAC of file at $path and write to
# "$path.hmac" with mode 0600. Refuses to operate on symlinks (defense
# against config-path symlink-tricks) and uses O_NOFOLLOW where the
# platform supports it.
sub write_for {
    my $config_path = shift;
    croak 'write_for: path required' unless defined $config_path;
    return unless -f $config_path;
    return if -l $config_path;       # never compute HMAC over a symlinked file
    init() unless defined $HMAC_KEY;

    my $hmac_path = "${config_path}.hmac";

    open(my $fh, '<:raw', $config_path) or return;
    local $/ = undef;
    my $data = <$fh>;
    close $fh;

    my $hmac = hmac_sha256_hex($data, $HMAC_KEY);

    # Anti-symlink hardening on the sidecar:
    #  - unlink any pre-existing symlink (else sysopen would follow it)
    #  - O_NOFOLLOW where supported, to refuse if a symlink is planted
    #    between our unlink and our open (TOCTOU window)
    if (-l $hmac_path) {
        unlink $hmac_path or do {
            warn "PAC::Crypto::HMAC: unlink stale symlink '$hmac_path' failed: $!\n";
            return;
        };
    }
    my $flags = O_WRONLY | O_CREAT | O_TRUNC;
    $flags |= Fcntl::O_NOFOLLOW() if defined &Fcntl::O_NOFOLLOW;
    if (sysopen(my $hfh, $hmac_path, $flags, 0600)) {
        print {$hfh} $hmac;
        close $hfh;
        chmod 0600, $hmac_path;
        return 1;
    }
    warn "PAC::Crypto::HMAC: cannot write sidecar '$hmac_path': $!\n";
    return;
}

# verify_for($config_path) — returns 1 if HMAC matches OR if there is no
# HMAC sidecar AND the config has no master_password_verifier (i.e. fresh
# install pre-HMAC era). Returns 0 on tamper.
sub verify_for {
    my $config_path = shift;
    croak 'verify_for: path required' unless defined $config_path;
    return 0 unless -f $config_path;
    init() unless defined $HMAC_KEY;

    my $hmac_path = "${config_path}.hmac";

    # Missing sidecar: only acceptable on a fresh, no-master-password install.
    # Otherwise an attacker could simply delete the .hmac to bypass integrity.
    if (!-f $hmac_path) {
        return 1 unless _has_master_verifier($config_path);
        print STDERR "SECURITY: '$config_path' has a master password set but no HMAC sidecar - refusing to load\n";
        return 0;
    }

    open(my $hfh, '<:raw', $hmac_path) or return 0;
    my $stored = <$hfh>;
    close $hfh;
    chomp $stored if defined $stored;

    open(my $fh, '<:raw', $config_path) or return 0;
    local $/ = undef;
    my $data = <$fh>;
    close $fh;

    my $computed = hmac_sha256_hex($data, $HMAC_KEY);
    return ct_eq($computed, $stored // '');
}

# ct_eq($a, $b) — constant-time string compare. Returns 1 iff equal.
sub ct_eq {
    my ($a, $b) = @_;
    return 0 unless defined $a && defined $b;
    return 0 unless length($a) == length($b);
    my $diff = 0;
    for my $i (0 .. length($a) - 1) {
        $diff |= ord(substr($a, $i, 1)) ^ ord(substr($b, $i, 1));
    }
    return $diff == 0;
}

#-------------------------------------------------------------------------
# Internal
#-------------------------------------------------------------------------

# Read a Storable file with code-execution disabled, return true if it
# contains a master_password_verifier.
sub _has_master_verifier {
    my $path = shift;
    my $found = 0;
    eval {
        local $Storable::Eval        = 0;
        local $Storable::Deparse     = 0;
        local $Storable::forgive_me  = 0;
        my $cfg = retrieve($path);
        $found = 1 if $cfg && ref($cfg) eq 'HASH'
            && defined $cfg->{defaults}{master_password_verifier}
            && $cfg->{defaults}{master_password_verifier} ne '';
    };
    return $found;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Crypto::HMAC — HMAC-SHA256 config-integrity helpers

=head1 SYNOPSIS

    use PAC::Crypto::HMAC;
    PAC::Crypto::HMAC::init({ cfg_dir => "$ENV{HOME}/.config/asbru" });

    PAC::Crypto::HMAC::write_for($cfg_path);   # writes $cfg_path.hmac

    if (!PAC::Crypto::HMAC::verify_for($cfg_path)) {
        die "config integrity check failed";
    }

=head1 DESCRIPTION

Three responsibilities, extracted from C<PACMain.pm> where they used to
live as private subs C<_writeConfigHMAC>, C<_verifyConfigHMAC>, C<_ct_eq>:

=over

=item 1.

Derive a per-installation HMAC key from the on-disk salt at
C<$cfg_dir/.salt>. Falls back to a static key if salt unavailable.

=item 2.

Compute and persist HMAC-SHA256 sidecars (C<$config_path.hmac>) with
mode 0600, refusing to write over symlinks, using C<O_NOFOLLOW> where
the platform supports it.

=item 3.

Verify HMAC sidecars at load time using constant-time string compare
(C<ct_eq>) to avoid timing oracles.

=back

=head1 SECURITY POSTURE

A missing HMAC sidecar is normally accepted (legacy / pre-HMAC config
files), B<except> when the config contains a C<master_password_verifier> —
then a missing sidecar is treated as tamper. This closes the trivial
"delete the .hmac" bypass.

C<verify_for> reads the config under C<Storable::Eval = 0> (code-execution
disabled) before checking the verifier, defending against malicious
Storable payloads.

=head1 PUBLIC API

=over

=item init(\%opts)

Initializes module state, deriving the HMAC key from the on-disk salt.
Idempotent. Options: C<cfg_dir>.

=item key

Returns the active HMAC key (hex string). Useful for tests; treat as
sensitive.

=item write_for($config_path)

Writes an HMAC-SHA256 sidecar at C<$config_path.hmac>. Returns 1 on
success, undef otherwise.

=item verify_for($config_path)

Returns 1 if the HMAC matches, 0 if tampered or missing-when-required.

=item ct_eq($a, $b)

Constant-time string compare. Returns 1 iff strings are byte-equal.

=back

=head1 SEE ALSO

L<PAC::Crypto::Cipher>, L<Digest::SHA>, L<SECURITY.md>.

=cut
