#!/usr/bin/perl
# t/19-vault-ct-compare.t
# Verify that PACUtils _verifyMasterPassword uses _ctEq (constant-time
# compare) on the decrypted token, removing the timing oracle on a
# wrong-vs-right master password.
use strict;
use warnings;
use Test::More tests => 9;
use FindBin qw($RealBin);

my $utils_pm = "$RealBin/../lib/PACUtils.pm";
ok(-r $utils_pm, 'PACUtils.pm is readable');

open(my $fh, '<', $utils_pm) or die "open $utils_pm: $!";
local $/;
my $src = <$fh>;
close $fh;

# After P2/2 + P2/3, the constant-time compare lives in PAC::Crypto::HMAC
# and _verifyMasterPassword lives in PAC::Vault. PACUtils retains proxies.
my $hmac_pm = "$RealBin/../lib/PAC/Crypto/HMAC.pm";
my $vault_pm = "$RealBin/../lib/PAC/Vault.pm";
my $cipher_pm = "$RealBin/../lib/PAC/Crypto/Cipher.pm";
open(my $hfh, '<', $hmac_pm); my $hmac_src = <$hfh>; close $hfh;
open(my $vfh, '<', $vault_pm); my $vault_src = <$vfh>; close $vfh;
open(my $cfh, '<', $cipher_pm); my $cipher_src = <$cfh>; close $cfh;

like($hmac_src, qr/sub ct_eq/,
    'PAC::Crypto::HMAC defines ct_eq constant-time compare');
like($src, qr/sub _verifyMasterPassword/,
    'PACUtils has _verifyMasterPassword (proxy)');
like($vault_src, qr/sub _verify\b/,
    'PAC::Vault has _verify implementation');
like($vault_src, qr/PAC::Crypto::HMAC::ct_eq\(\$plain/,
    'PAC::Vault::_verify uses ct_eq on decrypted token');

# encode_utf8 still in place — must remain so non-ASCII passwords work.
# Now lives in PAC::Crypto::Cipher::set_master and PAC::Vault::_verify.
like($cipher_src, qr/sub set_master.*?encode_utf8\(\$pass\)/s,
    'PAC::Crypto::Cipher::set_master encodes UTF-8 (non-ASCII master pwd works)');
like($vault_src, qr/encode_utf8\(\$master_pass\)/,
    'PAC::Vault::_verify encodes UTF-8 (non-ASCII master pwd works)');

# Lock GUI re-ciphers cleartext
my $main_pm = "$RealBin/../lib/PACMain.pm";
open(my $mfh, '<', $main_pm); local $/; my $msrc = <$mfh>; close $mfh;
like($msrc, qr/sub _lockAsbru.*?_cipherCFG\(\$\$self\{_CFG\}\)/s,
    '_lockAsbru re-ciphers cfg to wipe plaintext from memory');

# Defensive shutdown — blessed check on $self
like($msrc, qr/blessed\(\$self\).*?_saveTreeExpanded/s,
    '_quitProgram guards _saveTreeExpanded with blessed($self)');
