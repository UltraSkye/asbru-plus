package PAC::Storage::Yaml;

###############################################################################
# PAC::Storage::Yaml — safe wrapper around YAML::LoadFile / YAML::DumpFile.
#
# YAML allows embedded type tags like !!perl/code or !!perl/glob that, when
# parsed with $YAML::LoadBlessed = 1 (the default), instantiate arbitrary
# blessed objects whose DESTROY methods can run arbitrary code. A
# malicious YAML config file could then get arbitrary code execution at
# load time.
#
# Defense: this module FORCES $YAML::LoadBlessed = 0 at compile time
# (BEGIN block). All loads through here are safe regardless of what
# other modules might do to the global. Writes go through DumpFile
# unchanged — there's no equivalent attack on the write side.
#
# Migration:
#   - All NEW config-load code MUST use PAC::Storage::Yaml::load_file.
#   - Existing YAML::LoadFile callsites (6 in PACMain/PACEdit/PACConfig/
#     PACUtils/asbru-cm) are unchanged because they pick up the
#     LoadBlessed=0 setting from PACMain.pm:40 at startup. Migrating
#     them removes the order-of-load dependency.
###############################################################################

use strict;
use warnings;
use utf8;

use Carp qw(croak);
use YAML qw(LoadFile DumpFile);

# Force the safe default at compile time. Done in BEGIN so that even if
# something else in the process sets it to 1 later, our load_file/dump_file
# below will work — but if a caller bypasses this module and calls
# YAML::LoadFile directly, they get whatever the global is set to. The
# safety contract is "use this module".
BEGIN {
    $YAML::LoadBlessed = 0;
}

our $VERSION = '0.1.0';

#-------------------------------------------------------------------------
# Public API
#-------------------------------------------------------------------------

# load_file($path) -> deserialized data (or croaks)
# Always loads with $YAML::LoadBlessed = 0 (no blessed objects).
sub load_file {
    my $path = shift;
    croak 'load_file: path required' unless defined $path && $path ne '';
    croak "load_file: '$path' not readable" unless -r $path;

    # Re-enforce locally in case something else changed the global.
    local $YAML::LoadBlessed = 0;

    my $data;
    eval { $data = LoadFile($path); };
    if ($@) {
        croak "load_file: '$path' parse failed: $@";
    }
    return $data;
}

# dump_file($data, $path) -> 1 on success
# Wraps YAML::DumpFile. No security flags involved on the write side.
sub dump_file {
    my ($data, $path) = @_;
    croak 'dump_file: data required' unless defined $data;
    croak 'dump_file: path required' unless defined $path && $path ne '';

    DumpFile($path, $data) or croak "dump_file: '$path' write failed: $!";
    return 1;
}

# load_string($yaml_text) -> deserialized data (or croaks)
# For tests and programmatic use without touching the filesystem.
sub load_string {
    my $text = shift;
    croak 'load_string: text required' unless defined $text;

    local $YAML::LoadBlessed = 0;
    my $data;
    eval { $data = YAML::Load($text); };
    if ($@) {
        croak "load_string: parse failed: $@";
    }
    return $data;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Storage::Yaml — safe wrapper around YAML::LoadFile / YAML::DumpFile

=head1 SYNOPSIS

    use PAC::Storage::Yaml;

    # Read — always with LoadBlessed=0
    my $cfg = PAC::Storage::Yaml::load_file($path);

    # Write
    PAC::Storage::Yaml::dump_file($cfg, $path);

    # Round-trip in memory (tests)
    my $struct = PAC::Storage::Yaml::load_string("foo: 1\nbar: [a, b]\n");

=head1 DESCRIPTION

YAML allows embedded type tags such as C<!!perl/code> or C<!!perl/glob>
that, with C<$YAML::LoadBlessed = 1> (the YAML.pm default), instantiate
arbitrary blessed objects whose C<DESTROY> methods then run arbitrary
code at load time. A malicious config file could exploit this for
code execution.

This module forces C<$YAML::LoadBlessed = 0> in a C<BEGIN> block AND
re-applies it as a C<local> inside every load call, so even if
something else in the process flips the global the loads here remain
safe.

=head1 SECURITY POSTURE

Defensive layer only. This module:

=over

=item *

Refuses to deserialize blessed objects.

=item *

Does NOT validate the structure (use L<PAC::Config::Schema> for that).

=item *

Does NOT verify integrity (use L<PAC::Crypto::HMAC> sidecar files).

=back

For maximum safety, layer all three: HMAC-verify -> Storable/YAML-load
-> schema-validate.

=head1 PUBLIC API

=over

=item load_file($path)

Reads C<$path>, parses as YAML with C<LoadBlessed=0>, returns the
deserialized structure. Croaks on missing path, unreadable file, or
parse error.

=item dump_file($data, $path)

Serializes C<$data> to C<$path> as YAML. Returns 1 on success, croaks
on failure.

=item load_string($text)

Parses C<$text> as YAML and returns the structure. Useful for tests.

=back

=head1 SEE ALSO

L<YAML>, L<PAC::Storage::Storable>, L<PAC::Config::Schema>,
L<PAC::Crypto::HMAC>.

=cut
