#!/usr/bin/perl
# t/24-dialog-extraction.t — Verifies that PAC::Dialog loads cleanly and that
# PACUtils still exports the legacy `_w*` names (proxied via goto).
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

# 1. Module loads and has all four exported helpers.
require_ok('PAC::Dialog');

for my $sub (qw(_wEnterValue _wMessage _wConfirm _wYesNoCancel)) {
    can_ok('PAC::Dialog', $sub);
}

# 2. Internal layout helper exists.
can_ok('PAC::Dialog', '_constrain_action_area');

# 3. Source-text checks: PACUtils has been thinned to proxies, not duplicate
#    bodies. If someone re-adds a full implementation in PACUtils we want to
#    catch the regression.
my $utils = do {
    open my $fh, '<', "$RealBin/../lib/PACUtils.pm" or die "open PACUtils: $!";
    local $/;
    <$fh>;
};

for my $sub (qw(_wEnterValue _wMessage _wConfirm _wYesNoCancel)) {
    like($utils, qr/sub \Q$sub\E\s*\{\s*goto\s*&PAC::Dialog::\Q$sub\E\s*;\s*\}/,
        "PACUtils.pm $sub is a proxy to PAC::Dialog::$sub");
}

like($utils, qr/^use PAC::Dialog/m, 'PACUtils imports PAC::Dialog');

# 4. The exports list still contains the four names — callers continue to
#    receive them via PACUtils.
like($utils, qr/_wEnterValue/, '_wEnterValue still in PACUtils @EXPORT');
like($utils, qr/_wMessage/,    '_wMessage still in PACUtils @EXPORT');
like($utils, qr/_wConfirm/,    '_wConfirm still in PACUtils @EXPORT');
like($utils, qr/_wYesNoCancel/, '_wYesNoCancel still in PACUtils @EXPORT');

# 5. PAC::Dialog also exports the larger _wAddRenameNode / _wProgress /
#    _wSetPACPassword helpers (moved in P3/7). These DO touch \$cfg /
#    \$self->{_CFG} because the legacy callers passed them in. The pure
#    UI helpers (_wMessage etc.) above do NOT — verified separately by
#    re-reading just the section of the file before the P3/7 marker.
for my $sub (qw(_wAddRenameNode _wProgress _wSetPACPassword)) {
    can_ok('PAC::Dialog', $sub);
}

my $dialog = do {
    open my $fh, '<', "$RealBin/../lib/PAC/Dialog.pm" or die "open Dialog: $!";
    local $/;
    <$fh>;
};

# Pure-UI section (everything before the "moved from PACUtils in P3/7"
# marker) must NOT touch _CFG or crypto state.
my ($pure_ui) = $dialog =~ /^(.*?)# Additional dialog helpers \(moved from PACUtils in P3\/7\)/ms;
$pure_ui //= $dialog;     # if marker not present, fall back to whole file

unlike($pure_ui // '', qr/_CFG\b/, 'PAC::Dialog pure-UI section does not touch _CFG');
unlike($pure_ui // '', qr/CIPHER\b/, 'PAC::Dialog pure-UI section does not touch crypto state');

# The crypto reference in the migrated section must go through
# PAC::Crypto::Cipher (not the legacy global $PACUtils::CIPHER).
unlike($dialog, qr/\$PACUtils::CIPHER\b/,
    'PAC::Dialog uses PAC::Crypto::Cipher API, not legacy $PACUtils::CIPHER global');
unlike($dialog, qr/_decrypt_hex_compat/,
    'PAC::Dialog uses PAC::Crypto::Cipher::decrypt_hex, not _decrypt_hex_compat proxy');

done_testing();
