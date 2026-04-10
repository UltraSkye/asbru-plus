#!/usr/bin/perl
# t/22-vault-scaffold.t
# Static check that the PAC::Vault scaffold exists with the planned API
# surface so call sites can be migrated incrementally.
use strict;
use warnings;
use Test::More tests => 12;
use FindBin qw($RealBin);

my $vault_pm = "$RealBin/../lib/PAC/Vault.pm";
ok(-r $vault_pm, 'PAC::Vault.pm is readable');

open(my $fh, '<', $vault_pm) or die "open: $!";
local $/;
my $src = <$fh>;
close $fh;

like($src, qr/package PAC::Vault/, 'declares package PAC::Vault');
like($src, qr/sub instance/,        'has instance() singleton accessor');
like($src, qr/sub unlock/,          'has unlock()');
like($src, qr/sub verify/,          'has verify()');
like($src, qr/sub create_verifier/, 'has create_verifier()');
like($src, qr/sub encrypt_field/,   'has encrypt_field()');
like($src, qr/sub decrypt_field/,   'has decrypt_field()');
like($src, qr/sub kdf_strength/,    'has kdf_strength()');
like($src, qr/sub get_secret/,      'has get_secret() declared (future API)');
like($src, qr/sub rotate_kdf/,      'has rotate_kdf() declared (future Argon2id migration)');
like($src, qr/SECURITY\.md/,        'cross-references SECURITY.md in POD');
