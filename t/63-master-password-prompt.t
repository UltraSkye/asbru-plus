#!/usr/bin/perl
# t/63-master-password-prompt.t — PAC::Dialog::MasterPasswordPrompt surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::Dialog::MasterPasswordPrompt');
can_ok('PAC::Dialog::MasterPasswordPrompt', 'prompt');

my $src = do {
    open my $fh, '<',
        "$RealBin/../lib/PAC/Dialog/MasterPasswordPrompt.pm"
        or die "open: $!";
    local $/; <$fh>;
};

# Package + entry
like($src, qr/^package PAC::Dialog::MasterPasswordPrompt;/m,
    'declares package');
like($src, qr/^sub prompt\b/m, 'has prompt');

# First-run gate
like($src, qr/return if defined.*master_password_verifier/,
    'no-op when verifier already defined');

# Warning text mentions the security context
like($src, qr/Security Warning/, 'shows security warning header');
like($src, qr/default key.*public/i, 'mentions public default key');
like($src, qr/strongly recommended/i,
    'recommends setting master password');

# Helpers used
like($src, qr/PACUtils::_wConfirm/,        'uses _wConfirm for warning');
like($src, qr/PACUtils::_wEnterValue.*\n.*Set Master Password/s,
    'first prompt is "Set Master Password"');
like($src, qr/Confirm Master Password/, 'confirm prompt present');
like($src, qr/asbru-protected/, 'uses asbru-protected icon');

# Cipher switch + verifier
like($src, qr/PACUtils::_initMasterCipher\(\$new_pass\)/,
    'switches active cipher on accept');
like($src, qr/PACUtils::_createMasterVerifier\(\$new_pass\)/,
    'stores verifier on accept');
like($src, qr/Master password set/,
    'logs success to STDERR');

# Mismatch path: clears verifier to '' so it never re-asks
like($src, qr/Passwords did not match/, 'mismatch shown to user');
like($src, qr/master_password_verifier'\}\s*=\s*''/,
    'declined/mismatch path persists empty verifier');

# Persistence: minimal nstore + HMAC, NOT full _saveConfiguration
like($src, qr/use Storable qw\(nstore\)/, 'imports nstore');
like($src, qr/PAC::Crypto::HMAC::write_for/,
    'emits HMAC sidecar for verifier persistence');
like($src, qr/\$PACMain::CFG_FILE_NFREEZE/,
    'reads CFG_FILE_NFREEZE from PACMain');
like($src, qr/PACUtils::_cipherCFG/,
    're-encrypts before nstore');
like($src, qr/PACUtils::_decipherCFG/,
    'restores plaintext after nstore');

# Defensive: persistence is wrapped in eval{} with a warn on failure
like($src, qr/eval \{.*nstore.*\};.*if \(\$\@\)/s,
    'persistence is eval-guarded');
like($src, qr/Could not persist master_password_verifier/,
    'failure path warns to STDERR');

# PACMain wrapper
my $main = do {
    open my $fh, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$fh>;
};
like($main, qr/^require PAC::Dialog::MasterPasswordPrompt/m,
    'PACMain requires PAC::Dialog::MasterPasswordPrompt');
like($main, qr/sub _promptSetMasterPassword\s*\{\s*goto\s*&PAC::Dialog::MasterPasswordPrompt::prompt\s*;\s*\}/,
    '_promptSetMasterPassword proxy');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item prompt\b/m,    'POD =item prompt');

done_testing();
