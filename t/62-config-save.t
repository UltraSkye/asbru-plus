#!/usr/bin/perl
# t/62-config-save.t — PAC::Config::Save surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::Config::Save');
can_ok('PAC::Config::Save', 'save');

my $src = do {
    open my $fh, '<', "$RealBin/../lib/PAC/Config/Save.pm" or die "open: $!";
    local $/; <$fh>;
};

# Package + entry
like($src, qr/^package PAC::Config::Save;/m, 'declares package');
like($src, qr/^sub save\b/m,                 'has save');

# Pipeline steps
like($src, qr/_purgeUnusedOrMissingScreenshots/,
    'pipeline: purge screenshots');
like($src, qr/_cfgGetTmpSessions/, 'pipeline: snapshot temp sessions');
like($src, qr/_cfgSanityCheck/,    'pipeline: sanity check');
like($src, qr/_cipherCFG/,         'pipeline: encrypt passwords');
like($src, qr/_decipherCFG/,       'pipeline: decrypt back in memory');
like($src, qr/_cfgAddSessions/,    'pipeline: restore temp sessions');
like($src, qr/_saveTreeExpanded/,  'pipeline: save tree expanded state');
like($src, qr/saveStats/,          'pipeline: persist statistics');
like($src, qr/_setCFGChanged\(0\)/, 'pipeline: reset changed indicator');

# Read-only short-circuit
like($src, qr/return 1 if \$\$self\{_READONLY\}/,
    'read-only mode is a no-op');

# SECURITY: symlink refusal
like($src, qr/-l \$primary/, 'refuses symlinked primary config');
like($src, qr/return 0/,     'returns 0 when symlinked');
like($src, qr/O_NOFOLLOW/,   'uses O_NOFOLLOW on lock-file open');
like($src, qr/unlink \$lock_path if -l \$lock_path/,
    'drops stale symlink lock before O_NOFOLLOW open');

# Locking
like($src, qr/use Fcntl qw\(:flock\)/, 'imports flock constants');
like($src, qr/LOCK_EX/, 'uses LOCK_EX');
like($src, qr/LOCK_UN/, 'releases via LOCK_UN');

# Storage + HMAC
like($src, qr/use Storable qw\(nstore\)/, 'imports nstore');
like($src, qr/PAC::Crypto::HMAC::write_for/,
    'emits HMAC sidecar for primary');

# REGRESSION: HMAC sidecar must be emitted ONLY when nstore succeeds.
# Otherwise the sidecar would validate stale/missing primary content
# and the next load would silently accept stale config as authentic.
like($src, qr/if \(nstore\(\$cfg, \$primary\)\) \{\s*\n\s*PAC::Crypto::HMAC::write_for\(\$primary\)/s,
    'HMAC sidecar gated on nstore success (primary)');
like($src, qr/if \(nstore\(\$cfg, \$PACMain::R_CFG_FILE\)\) \{\s*\n\s*PAC::Crypto::HMAC::write_for\(\$PACMain::R_CFG_FILE\)/s,
    'HMAC sidecar gated on nstore success (replica)');

# Replica path handling
like($src, qr/\$PACMain::R_CFG_FILE/, 'reads $PACMain::R_CFG_FILE');
like($src, qr/\$PACMain::CFG_FILE_NFREEZE/,
    'reads $PACMain::CFG_FILE_NFREEZE');

# PACMain wrapper
my $main = do {
    open my $fh, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$fh>;
};
like($main, qr/^require PAC::Config::Save/m,
    'PACMain requires PAC::Config::Save');
like($main, qr/sub _saveConfiguration\s*\{\s*goto\s*&PAC::Config::Save::save\s*;\s*\}/,
    '_saveConfiguration proxy');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item save\b/m,      'POD =item save');
like($src, qr/^=head1 SECURITY/m,   'POD: SECURITY section');

done_testing();
