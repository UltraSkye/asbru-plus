package PAC::Util::ShellEscape;

###############################################################################
# PAC::Util::ShellEscape — minimal shell-string escape helper.
#
# Backslash-escapes shell metacharacters ($\\`"!) and converts \n / \r
# to their literal two-character forms (\\n / \\r). Used when embedding
# user-controlled values inside double-quoted shell strings.
#
# Mechanical extraction from PACUtils::_doShellEscape. PACUtils retains
# a 1-line goto-proxy.
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# escape($string) — backslash-escapes shell metacharacters.
# Returns the escaped string. Caller is responsible for embedding in
# double quotes.
sub escape {
    my $str = shift;
    return '' unless defined $str;
    $str =~ s/([\$\\`"!])/\\$1/g;
    $str =~ s/\n/\\n/g;
    $str =~ s/\r/\\r/g;
    return $str;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Util::ShellEscape — minimal shell-string escape helper

=head1 SYNOPSIS

    use PAC::Util::ShellEscape;

    my $safe = PAC::Util::ShellEscape::escape($user_input);
    system(qq{echo "$safe"});

=head1 DESCRIPTION

Backslash-escapes shell metacharacters: C<$>, C<\>, C<`>, C<">, C<!>.
Converts newlines and carriage returns to their literal two-character
forms. Designed for embedding user-controlled strings inside
double-quoted shell arguments.

This is NOT a full shell-escape — it does NOT handle single quotes,
heredocs, or operator chars like C<;>, C<|>, C<&>. For high-security
contexts, use C<system(LIST)> with array-form arguments instead, which
bypasses the shell entirely.

=head1 PUBLIC API

=over

=item escape($string)

Returns C<$string> with shell metacharacters backslash-escaped.
Returns the empty string for undef input.

=back

=head1 SEE ALSO

L<PAC::Subst>, L<perlsec/Cleaning Up Your Path>.

=cut
