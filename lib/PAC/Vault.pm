package PAC::Vault;

# PAC::Vault — skeleton for the credential store extraction.
#
# THIS IS A SCAFFOLD. The audit identified the global $PACUtils::CIPHER
# pattern + cleartext passwords in the cfg hash as the highest-leverage
# refactor target. The full extraction (decrypt-on-demand, Argon2id KDF,
# versioned envelope, in-memory zeroization) is a multi-week effort.
#
# This module exists today to give callers a stable namespace to migrate
# *to*, even while the underlying implementation still delegates to
# PACUtils for backward compat. New code should write against PAC::Vault
# from day one; legacy paths can be ported one at a time.

use strict;
use warnings;
use utf8;

use Carp qw(croak);

our $VERSION = '0.1.0';

# Singleton — only ever one active vault per process. Future: scope to
# an instance and remove all module-level state from PACUtils.
my $INSTANCE;

sub instance {
    my $class = shift;
    $INSTANCE //= $class->_new(@_);
    return $INSTANCE;
}

sub _new {
    my ($class, %args) = @_;
    my $self = {
        cfg_path => $args{cfg_path},
        unlocked => 0,
        kdf_version => 1,   # 1 = legacy opensslv2; 2 = future Argon2id
    };
    return bless $self, $class;
}

# is_unlocked — true once the user has supplied a master password (or
# the legacy default cipher is in use).
sub is_unlocked {
    my $self = shift;
    require PACUtils;
    return PACUtils::_isMasterPasswordActive() || 1;
}

# unlock($master_password) — switches the active cipher to a key derived
# from the supplied master password. Returns true on success.
sub unlock {
    my ($self, $master_pass) = @_;
    croak "missing master password" unless defined $master_pass;
    require PACUtils;
    PACUtils::_initMasterCipher($master_pass);
    $self->{unlocked} = 1;
    return 1;
}

# verify($master_password, $verifier) — constant-time check of a
# password against a stored verifier. Returns true/false.
sub verify {
    my ($self, $master_pass, $verifier) = @_;
    require PACUtils;
    return PACUtils::_verifyMasterPassword($master_pass, $verifier);
}

# create_verifier($master_password) — produce a verifier blob to store
# in the cfg, used to authenticate the user on next unlock without
# needing to decrypt the whole config.
sub create_verifier {
    my ($self, $master_pass) = @_;
    require PACUtils;
    return PACUtils::_createMasterVerifier($master_pass);
}

# encrypt_field($plaintext) / decrypt_field($ciphertext) — single-field
# operations. Today: thin wrappers around PACUtils. Future: take a
# context (uuid, field name) so we can audit-log every secret access.
sub encrypt_field {
    my ($self, $plain) = @_;
    return '' unless defined $plain && length $plain;
    require PACUtils;
    no warnings 'once';
    return $PACUtils::CIPHER->encrypt_hex($plain);
}

sub decrypt_field {
    my ($self, $ciphertext) = @_;
    return '' unless defined $ciphertext && length $ciphertext;
    require PACUtils;
    my $plain;
    eval { $plain = PACUtils::_decrypt_hex_compat($ciphertext); };
    return $@ ? '' : $plain;
}

# kdf_strength — returns a string describing the current KDF in use,
# for SECURITY.md / debug output. Will become a real version field once
# the Argon2 migration lands.
sub kdf_strength {
    my $self = shift;
    return 'pbkdf2-hmac-sha256/opensslv2 (legacy, 10k iter)';
}

# Future API surface — declared so callers can write against it today
# and the implementation can land later without an API break.
sub get_secret  { croak "PAC::Vault::get_secret not yet implemented (decrypt-on-demand)"; }
sub put_secret  { croak "PAC::Vault::put_secret not yet implemented" }
sub rotate_kdf  { croak "PAC::Vault::rotate_kdf not yet implemented (Argon2id migration)"; }
sub zero_memory { croak "PAC::Vault::zero_memory not yet implemented" }

1;

__END__

=head1 NAME

PAC::Vault - credential storage facade for Ásbrú Plus

=head1 SYNOPSIS

    use PAC::Vault;
    my $vault = PAC::Vault->instance(cfg_path => '/path/to/asbru.nfreeze');

    if (!$vault->verify($pwd, $verifier)) {
        die "wrong password";
    }
    $vault->unlock($pwd);

    my $cipher = $vault->encrypt_field('secret123');
    my $plain  = $vault->decrypt_field($cipher);

=head1 STATUS

This is a B<scaffold>. The active implementation still delegates to
the legacy C<PACUtils::$CIPHER> singleton. The intent is that all new
code uses C<PAC::Vault> as the namespace, and legacy callers in
C<PACMain> / C<PACEdit> / C<PACTerminal> are ported to it incrementally.

The full implementation (decrypt-on-demand, Argon2id KDF, in-memory
zeroization, audit log) is tracked in C<SECURITY.md> under "Known
weaknesses" and the audit roadmap.

=head1 SEE ALSO

L<SECURITY.md>, L<ARCHITECTURE.md>

=cut
