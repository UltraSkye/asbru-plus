package PAC::Config::Schema;

###############################################################################
# PAC::Config::Schema — JSON-Schema-style validator for asbru config keys.
#
# The legacy PACUtils::_cfgSanityCheck (559 lines) does ad-hoc validation
# inline: 'if (!defined $$cfg{defaults}{foo}) { $$cfg{defaults}{foo} = 0 }'.
# That works but it's untestable in isolation, has no formal type system,
# and silently accepts garbage values.
#
# This module provides a small validator that:
#   - declares the SHAPE of a config key (type, default, allowed values)
#   - returns errors as structured data (not warnings buried in stderr)
#   - is testable without loading PACMain / PACUtils
#
# Migration policy:
#   - DO NOT replace _cfgSanityCheck wholesale — too risky.
#   - DO declare new keys here as they are added (e.g. v6.5.0 settings).
#   - Existing keys migrate opportunistically; until then both layers
#     coexist (schema validation is informational, _cfgSanityCheck still
#     applies defaults).
###############################################################################

use strict;
use warnings;
use utf8;

use Carp qw(croak);

our $VERSION = '0.1.0';

#-------------------------------------------------------------------------
# Schema registry — keyed by dotted path within $cfg{defaults}.
#-------------------------------------------------------------------------
#
# Each entry is:
#   {
#     type    => 'bool' | 'int' | 'string' | 'enum' | 'path',
#     default => $value,
#     enum    => [...],      # for type=enum
#     min     => $n,         # for type=int
#     max     => $n,         # for type=int
#     since   => '6.5.0',    # documentation only
#   }
#
# Start with the v6.5.0 keys this fork introduced — these are uniquely
# our schema, not inherited from upstream's _cfgSanityCheck.

my %SCHEMA = (
    'defaults.disable bold' => {
        type    => 'bool',
        default => 0,
        since   => '6.5.0',
    },
    'defaults.hide info tab' => {
        type    => 'bool',
        default => 0,
        since   => '6.5.0',
    },
    'defaults.theme' => {
        type    => 'enum',
        enum    => [qw(default asbru-color asbru-dark system)],
        default => 'default',
    },
    'defaults.bold is brigth' => {  # sic — typo preserved for compat
        type    => 'bool',
        default => 0,
    },
    'defaults.start maximized' => {
        type    => 'bool',
        default => 0,
    },
    'defaults.tabs in main window' => {
        type    => 'bool',
        default => 1,
    },
    'defaults.terminal scrollback lines' => {
        type    => 'int',
        min     => -1,          # -1 = unlimited
        max     => 100_000,
        default => 5000,
    },
    'defaults.session logs amount' => {
        type    => 'int',
        min     => 1,
        max     => 1000,
        default => 10,
    },
);

#-------------------------------------------------------------------------
# Public API
#-------------------------------------------------------------------------

# all_keys() -> sorted list of declared dotted paths
sub all_keys { my @keys = sort keys %SCHEMA; return @keys; }

# get($path) -> hashref of declared schema, or undef
sub get { return $SCHEMA{$_[0]}; }

# default_for($path) -> declared default value, or undef
sub default_for {
    my $entry = $SCHEMA{$_[0]};
    return $entry ? $entry->{default} : undef;
}

# validate_value($path, $value) -> ($ok, $error?)
# Returns (1) if valid, (0, 'reason') if not. Unknown paths return (1)
# (we don't gate on completeness — only on declared keys).
sub validate_value {
    my ($path, $value) = @_;
    my $s = $SCHEMA{$path};
    return 1 unless $s;     # unknown key — skip (not our concern)

    my $type = $s->{type};
    if ($type eq 'bool') {
        return (0, "expected bool (0/1), got " . _show($value))
            unless defined $value && $value =~ /^[01]$/;
    } elsif ($type eq 'int') {
        return (0, "expected integer, got " . _show($value))
            unless defined $value && $value =~ /^-?\d+$/;
        if (defined $s->{min} && $value < $s->{min}) {
            return (0, "value $value below min $s->{min}");
        }
        if (defined $s->{max} && $value > $s->{max}) {
            return (0, "value $value above max $s->{max}");
        }
    } elsif ($type eq 'enum') {
        my %allowed = map { $_ => 1 } @{$s->{enum}};
        return (0, "value " . _show($value) . " not in allowed: "
                . join(',', @{$s->{enum}}))
            unless defined $value && $allowed{$value};
    } elsif ($type eq 'string') {
        return (0, 'expected string') unless defined $value && !ref $value;
    } elsif ($type eq 'path') {
        return (0, 'expected path string')
            unless defined $value && !ref $value && length $value;
    } else {
        croak "PAC::Config::Schema: unknown type '$type' for $path";
    }
    return 1;
}

# validate_cfg(\%cfg) -> arrayref of { path, value, error }
# Walks declared schema entries, checks each against $cfg, returns a list
# of validation failures. Empty arrayref = all valid.
sub validate_cfg {
    my $cfg = shift;
    croak 'validate_cfg requires hashref' unless ref $cfg eq 'HASH';

    my @errors;
    for my $path (sort keys %SCHEMA) {
        my $val = _lookup($cfg, $path);
        next unless defined $val;     # apply_defaults handles missing
        my ($ok, $err) = validate_value($path, $val);
        next if $ok;
        push @errors, { path => $path, value => $val, error => $err };
    }
    return \@errors;
}

# apply_defaults(\%cfg) -> count of keys filled in
# Walks declared schema, fills in any missing keys with their declared
# default. Existing values are NOT overwritten, even if invalid — that's
# what validate_cfg is for.
sub apply_defaults {
    my $cfg = shift;
    croak 'apply_defaults requires hashref' unless ref $cfg eq 'HASH';

    my $filled = 0;
    for my $path (keys %SCHEMA) {
        my $entry = $SCHEMA{$path};
        next unless exists $entry->{default};
        if (!defined _lookup($cfg, $path)) {
            _assign($cfg, $path, $entry->{default});
            $filled++;
        }
    }
    return $filled;
}

#-------------------------------------------------------------------------
# Internal helpers
#-------------------------------------------------------------------------

sub _show {
    my $v = shift;
    return 'undef' unless defined $v;
    return ref($v) ? '<' . ref($v) . '>' : "'$v'";
}

# _lookup(\%cfg, 'a.b.c') -> $cfg{a}{b}{c} or undef
sub _lookup {
    my ($cfg, $path) = @_;
    my @parts = split /\./, $path;
    my $node = $cfg;
    for my $p (@parts) {
        return unless ref $node eq 'HASH' && exists $node->{$p};
        $node = $node->{$p};
    }
    return $node;
}

# _assign(\%cfg, 'a.b.c', $v) -> set $cfg{a}{b}{c} = $v, autoviv intermediate
sub _assign {
    my ($cfg, $path, $v) = @_;
    my @parts = split /\./, $path;
    my $last  = pop @parts;
    my $node  = $cfg;
    for my $p (@parts) {
        $node->{$p} //= {};
        $node = $node->{$p};
    }
    $node->{$last} = $v;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Config::Schema — declarative validator for asbru config keys

=head1 SYNOPSIS

    use PAC::Config::Schema;

    # Apply defaults to a freshly-loaded config
    my $filled = PAC::Config::Schema::apply_defaults(\%cfg);

    # Validate before save
    my $errs = PAC::Config::Schema::validate_cfg(\%cfg);
    if (@$errs) {
        for my $e (@$errs) {
            warn "config: $e->{path} invalid ($e->{error})";
        }
    }

    # Single-key checks
    my $def = PAC::Config::Schema::default_for('defaults.theme');
    my ($ok, $why) = PAC::Config::Schema::validate_value(
        'defaults.theme', 'invalid-name');

=head1 DESCRIPTION

Declares the shape of asbru config keys (type, default, allowed values)
in a single registry. Replaces — gradually — the inline checks scattered
through C<PACUtils::_cfgSanityCheck>.

Coexistence policy: this module's C<apply_defaults> only fills in
missing keys; it never overwrites existing values, even if they are
invalid. Legacy code in C<_cfgSanityCheck> continues to coerce values.

=head1 REGISTERED KEY TYPES

=over

=item bool

Value must be 0 or 1.

=item int

Value must match C</^-?\d+$/>. Optional C<min> / C<max> bounds.

=item enum

Value must be one of the entries in the C<enum> arrayref.

=item string

Any defined non-reference scalar.

=item path

Like string, but must have non-zero length.

=back

=head1 PUBLIC API

=over

=item all_keys

Returns a sorted list of declared dotted paths.

=item get($path)

Returns the schema hashref for a declared path, or undef.

=item default_for($path)

Returns the declared default value, or undef.

=item validate_value($path, $value)

Returns C<(1)> if valid, C<(0, $reason)> if not. Unknown paths
return valid (this module gates on declared keys only).

=item validate_cfg(\%cfg)

Walks declared schema entries against C<$cfg>, returns an arrayref of
C<{ path, value, error }> entries for each failure.

=item apply_defaults(\%cfg)

Fills in any missing declared keys with their default value. Returns
the count of keys filled.

=back

=head1 SEE ALSO

L<PACUtils/_cfgSanityCheck>, L<ARCHITECTURE.md>.

=cut
