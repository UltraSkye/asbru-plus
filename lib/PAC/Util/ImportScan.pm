package PAC::Util::ImportScan;

###############################################################################
# PAC::Util::ImportScan — recursive scan of an imported config structure
# for shell-injection patterns.
#
# Walks an arbitrary HASH/ARRAY structure (typically the output of
# YAML::LoadFile) and counts strings that contain known-dangerous
# patterns: command substitution, reverse shells, alternative
# interpreters, common exfiltration tools, etc.
#
# Used by PACMain::__importNodes to warn the user before applying
# an untrusted YAML file.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# scan($data) — returns ($count, $first_detail) where $count is the
# number of suspicious strings found and $first_detail is a
# "path: value" preview of the first one (truncated at 200 chars).
sub scan {
    my $data = shift;
    return (0, '') unless defined $data;

    my $count  = 0;
    my $detail = '';

    my $walk;
    $walk = sub {
        my ($val, $path) = @_;
        if (ref($val) eq 'HASH') {
            for my $k (keys %$val) {
                $walk->($val->{$k}, "$path/$k");
            }
        } elsif (ref($val) eq 'ARRAY') {
            for my $i (0 .. $#$val) {
                $walk->($val->[$i], "$path/[$i]");
            }
        } elsif (!ref($val) && defined $val) {
            if (_is_suspicious($val)) {
                $count++;
                $detail = "at $path: $val" if $count == 1;
            }
        }
    };
    $walk->($data, 'root');

    return ($count, $detail);
}

# _is_suspicious($string) — returns true if $string matches any of
# the known shell-injection patterns. Public-ish helper, exposed
# for testing the regex independently of the walker.
sub _is_suspicious {
    my $s = shift;
    return 0 unless defined $s && !ref $s;

    # Patterns we flag (reordered + commented for readability):
    return 1 if $s =~ /\$\(/;                       # command substitution $(...)
    return 1 if $s =~ /`[^`]+`/;                    # backtick substitution
    return 1 if $s =~ /\beval\b/;                   # eval keyword
    return 1 if $s =~ /\bexec\b/;                   # exec keyword
    return 1 if $s =~ /\bsystem\b/;                 # system keyword
    return 1 if $s =~ /\brm\s+-rf\b/;               # forced recursive remove
    return 1 if $s =~ /;\s*(?:curl|wget|bash|sh|nc|ncat)\b/;  # ; curl/wget/sh
    return 1 if $s =~ /\|\s*(?:bash|sh|nc|ncat|python|perl|ruby|php)\b/;  # piped to interp
    return 1 if $s =~ m{/dev/tcp/};                 # bash /dev/tcp reverse-shell
    return 1 if $s =~ /\bmkfifo\b/;                 # named pipe (FIFO)
    return 1 if $s =~ /\bsocat\b/;                  # socat (often used for shells)
    return 1 if $s =~ /(?:python|perl|ruby|php)\d*\s+-[cerpw]/;  # interpreter -c/-e
    return 1 if $s =~ />\s*\//;                     # redirect to absolute path
    return 1 if $s =~ /<<\s*\bEOF\b/;               # heredoc
    return 0;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Util::ImportScan — scan imported config data for shell-injection patterns

=head1 SYNOPSIS

    use PAC::Util::ImportScan;

    my ($count, $first) = PAC::Util::ImportScan::scan($yaml_data);
    if ($count > 0) {
        warn "Found $count suspicious patterns; first: $first";
    }

=head1 DESCRIPTION

Recursive walker over an arbitrary nested structure (typically the
output of L<YAML::LoadFile>) that counts strings containing known
shell-injection patterns. Used by C<PACMain::__importNodes> as a
defense-in-depth gate before applying an untrusted YAML import.

The flagged patterns are documented inline in C<_is_suspicious>:
command substitution, reverse shells, alternative interpreters,
common exfiltration tools, etc.

This is a B<heuristic gate>, not a complete defense — a determined
attacker can craft strings that don't match any pattern. The user
is warned and asked to confirm; the actual safety guarantee comes
from how the imported strings are used elsewhere
(e.g. L<PAC::Subst>'s whitelist on C<E<lt>CMD:E<gt>>).

=head1 PUBLIC API

=over

=item scan($data)

Returns C<(\$count, \$first_detail)> — the number of suspicious
strings found and a "path: value" preview of the first one.

=item _is_suspicious($string)

Predicate for a single string. Public-ish — exposed for testing
the regex independently of the walker.

=back

=head1 SEE ALSO

L<PAC::Subst>, L<PAC::Storage::Yaml>, L<SECURITY.md>.

=cut
