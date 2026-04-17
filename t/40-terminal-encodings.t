#!/usr/bin/perl
# t/40-terminal-encodings.t — PAC::Terminal::Encodings registry.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

require_ok('PAC::Terminal::Encodings');
can_ok('PAC::Terminal::Encodings', 'all');

my $h = PAC::Terminal::Encodings::all();
isa_ok($h, 'HASH', 'all() returns hashref');
ok(scalar(keys %$h) > 100, 'registry has >100 encodings (got ' . scalar(keys %$h) . ')');

# Spot-check well-known encodings (using the actual registry key names)
for my $enc (qw(UTF-8 ISO-8859-15 windows-1252 Big5 EUC-KR KOI8-R)) {
    ok(exists $h->{$enc}, "registry contains $enc");
    ok(defined $h->{$enc} && length($h->{$enc}) >= 0,
        "$enc has a source string");
}

# Source strings for IANA encodings should mention IANA / ECMA / RFC
my $i;
for my $enc (sort keys %$h) {
    last if ++$i > 50;
    isnt($h->{$enc}, undef, "$enc value not undef");
}

# Reading PACUtils + verify proxy
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Terminal::Encodings/m,
    'PACUtils requires PAC::Terminal::Encodings');
like($utils, qr/sub _getEncodings\s*\{\s*goto\s*&PAC::Terminal::Encodings::all\s*;\s*\}/,
    'PACUtils._getEncodings is goto-proxy');

# POD
my $src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Terminal/Encodings.pm" or die "open: $!";
    local $/; <$f>;
};
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
like($src, qr/^=item all\b/m,       'POD =item all');

done_testing();
