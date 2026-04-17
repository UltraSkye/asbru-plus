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
    return undef unless defined $body;

    my ($tag)      = $body =~ /"tag_name"\s*:\s*"([^"]+)"/;
    my ($html_url) = $body =~ /"html_url"\s*:\s*"([^"]+)"/;
    return undef unless defined $tag && length $tag;

    return {
        tag      => $tag,
        html_url => $html_url
                 // 'https://github.com/UltraSkye/asbru-plus/releases',
    };
}

# is_newer($latest_tag, $current_version) — string-compare two version
# tags ignoring a leading 'v'. Returns true if $latest_tag > $current.
# Mirror of the comparison done in PACMain::_checkForUpdates.
sub is_newer {
    my ($latest, $current) = @_;
    return 0 unless defined $latest && defined $current;
    (my $l = $latest)  =~ s/^v//i;
    (my $c = $current) =~ s/^v//i;
    return $l gt $c;
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
