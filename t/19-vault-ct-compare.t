#!/usr/bin/perl
# t/19-vault-ct-compare.t
# Verify that PACUtils _verifyMasterPassword uses _ctEq (constant-time
# compare) on the decrypted token, removing the timing oracle on a
# wrong-vs-right master password.
use strict;
use warnings;
use Test::More tests => 7;
use FindBin qw($RealBin);

my $utils_pm = "$RealBin/../lib/PACUtils.pm";
ok(-r $utils_pm, 'PACUtils.pm is readable');

open(my $fh, '<', $utils_pm) or die "open $utils_pm: $!";
local $/;
my $src = <$fh>;
close $fh;

like($src, qr/sub _ctEq/,
    'PACUtils defines _ctEq constant-time compare');
like($src, qr/sub _verifyMasterPassword/,
    'PACUtils has _verifyMasterPassword');
like($src, qr/_ctEq\(\$result/,
    '_verifyMasterPassword uses _ctEq on decrypted token');

# encode_utf8 still in place — must remain so non-ASCII passwords work
like($src, qr/_initMasterCipher.*?encode_utf8\(\$master_pass\)/s,
    '_initMasterCipher still encodes UTF-8 (regression: non-ASCII master pwd)');

# Lock GUI re-ciphers cleartext
my $main_pm = "$RealBin/../lib/PACMain.pm";
open(my $mfh, '<', $main_pm); local $/; my $msrc = <$mfh>; close $mfh;
like($msrc, qr/sub _lockAsbru.*?_cipherCFG\(\$\$self\{_CFG\}\)/s,
    '_lockAsbru re-ciphers cfg to wipe plaintext from memory');

# Defensive shutdown — blessed check on $self
like($msrc, qr/blessed\(\$self\).*?_saveTreeExpanded/s,
    '_quitProgram guards _saveTreeExpanded with blessed($self)');
