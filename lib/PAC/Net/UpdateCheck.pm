package PAC::Net::UpdateCheck;

###############################################################################
# PAC::Net::UpdateCheck — fetch the latest asbru-plus release tag from
# GitHub.
#
# Pure-ish: only side effect is the HTTP GET. Returns a structured
# result the caller can compare against its own version + use to
# update its own UI. Used by PACMain at startup to decide whether to
# show the "new version available" banner.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# fetch_latest($url?) — GET the GitHub releases/latest endpoint and
# parse out tag_name + html_url from the JSON. Returns:
#   { tag => 'v6.5.0', html_url => 'https://...' }
# on success, or undef on any failure (network, JSON, missing fields).
#
# Uses HTTP::Tiny with a 4-second timeout. Lazy-loads HTTP::Tiny so
# the dep is paid only when the function is called.
sub fetch_latest {
    my $url = shift
        // 'https://api.github.com/repos/UltraSkye/asbru-plus/releases/latest';

    my $body;
    eval {
        require HTTP::Tiny;
        my $resp = HTTP::Tiny->new(timeout => 4)->get($url);
        $body = $resp->{content} if $resp->{success};
    };
    return unless defined $body;

    my ($tag)      = $body =~ /"tag_name"\s*:\s*"([^"]+)"/;
    my ($html_url) = $body =~ /"html_url"\s*:\s*"([^"]+)"/;
    return unless defined $tag && length $tag;

    return {
        tag      => $tag,
        html_url => $html_url
                 // 'https://github.com/UltraSkye/asbru-plus/releases',
    };
}

# is_newer($latest_tag, $current_version) — compare two semver-ish
# version tags ignoring a leading 'v'. Returns true if $latest_tag is
# strictly newer than $current.
#
# Component-wise NUMERIC comparison: '6.10.0' is correctly newer than
# '6.9.0' (the previous string-compare implementation said no, because
# '6.1' sorts before '6.9' lexically — a real bug that meant nobody
# upgrading from 6.9 to 6.10+ would ever see the "update available"
# banner).
#
# Non-numeric trailers (e.g. '6.6.0-rc1') compare lexically as a
# tiebreaker after the numeric prefix matches. Tags with strictly
# fewer components are treated as zero-padded ('6.5' == '6.5.0').
sub is_newer {
    my ($latest, $current) = @_;
    return 0 unless defined $latest && defined $current;
    (my $l = $latest)  =~ s/^v//i;
    (my $c = $current) =~ s/^v//i;

    my @lp = split /\./, $l;
    my @cp = split /\./, $c;
    my $n = scalar(@lp) > scalar(@cp) ? scalar(@lp) : scalar(@cp);
    for my $i (0 .. $n - 1) {
        my $a = $lp[$i] // '0';
        my $b = $cp[$i] // '0';
        # Strict numeric comparison if BOTH components parse as ints.
        if ($a =~ /^\d+$/ && $b =~ /^\d+$/) {
            return 1 if $a + 0 > $b + 0;
            return 0 if $a + 0 < $b + 0;
        } else {
            # Mixed / pre-release ('rc1', 'beta') — fall back to
            # lexical compare on this component.
            return 1 if $a gt $b;
            return 0 if $a lt $b;
        }
    }
    return 0;   # all components equal → not newer
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Net::UpdateCheck — GitHub release-tag check for asbru-plus

=head1 SYNOPSIS

    use PAC::Net::UpdateCheck;

    if (my $rel = PAC::Net::UpdateCheck::fetch_latest()) {
        if (PAC::Net::UpdateCheck::is_newer($rel->{tag}, $current_version)) {
            print "Update available: $rel->{tag} ($rel->{html_url})\n";
        }
    }

=head1 DESCRIPTION

Tiny HTTP client wrapper around the GitHub
C</releases/latest> JSON endpoint. Used by C<PACMain> at startup to
decide whether to show the "new version available" banner.

The HTTP fetch is pure (no side effects on caller state); the version
comparison is also pure. The caller is responsible for updating UI
based on the result.

Mechanical extraction from the network half of
C<PACMain::_checkForUpdates>; PACMain retains the 3-line UI-mutation
half (banner label + show()).

=head1 PUBLIC API

=over

=item fetch_latest($url?)

GETs the GitHub releases/latest endpoint with a 4-second timeout.
Returns C<{ tag, html_url }> hashref on success or C<undef> on any
failure (network error, JSON parse, missing tag_name).

C<$url> defaults to the asbru-plus repo. Override for testing or
forks.

=item is_newer($latest_tag, $current_version)

String-compares two version tags ignoring leading C<v>. Returns true
if C<\$latest_tag> sorts later than C<\$current_version>.

=back

=head1 SEE ALSO

L<HTTP::Tiny>, L<https://docs.github.com/en/rest/releases>.

=cut
