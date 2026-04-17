#!/usr/bin/perl
# t/25-wol-extraction.t — PAC::WakeOnLan extraction & magic-packet builder.
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::WakeOnLan');

can_ok('PAC::WakeOnLan', $_) for qw(magic_packet send_magic_packet _wakeOnLan);

# 1. magic_packet shape: 102 bytes = 6×0xFF + 16×6-byte MAC.
my $pkt = PAC::WakeOnLan::magic_packet('00:11:22:33:44:55');
is(length($pkt), 102, 'magic packet is 102 bytes');
is(substr($pkt, 0, 6), "\xff\xff\xff\xff\xff\xff", 'first six bytes are 0xFF');
is(substr($pkt, 6, 6), pack('H12', '001122334455'), 'first MAC repetition matches');
is(substr($pkt, 96, 6), pack('H12', '001122334455'), 'last MAC repetition matches');

# 2. Accepts dash separator and mixed case.
my $pkt_dash = PAC::WakeOnLan::magic_packet('AA-bb-CC-dd-EE-ff');
is(substr($pkt_dash, 6, 6), pack('H12', 'aabbccddeeff'), 'dash + mixed-case MAC accepted');

# 3. Rejects malformed input.
eval { PAC::WakeOnLan::magic_packet('not-a-mac') };
like($@, qr/malformed MAC/, 'rejects non-MAC string');
eval { PAC::WakeOnLan::magic_packet() };
like($@, qr/MAC required/, 'rejects missing arg');
eval { PAC::WakeOnLan::magic_packet('00:11:22:33:44') };
like($@, qr/malformed MAC/, 'rejects 5-byte MAC');

# 4. PACUtils.pm now proxies _wakeOnLan to PAC::WakeOnLan.
my $utils = do {
    open my $fh, '<', "$RealBin/../lib/PACUtils.pm" or die "open PACUtils: $!";
    local $/;
    <$fh>;
};
like($utils, qr/sub _wakeOnLan\s*\{\s*goto\s*&PAC::WakeOnLan::_wakeOnLan/,
    'PACUtils._wakeOnLan is a goto-proxy to PAC::WakeOnLan::_wakeOnLan');
like($utils, qr/^use PAC::WakeOnLan/m, 'PACUtils imports PAC::WakeOnLan');
unlike($utils, qr/^\s+# Prepare the magic packet/m,
    'old packet-build code no longer present in PACUtils');

# 5. PACUtils still exports _wakeOnLan to legacy callers.
like($utils, qr/_wakeOnLan/, '_wakeOnLan still in PACUtils @EXPORT');

done_testing();
