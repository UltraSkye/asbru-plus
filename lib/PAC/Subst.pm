package PAC::Subst;

###############################################################################
# PAC::Subst — template-variable substitution engine.
#
# Replaces template tags in connection-related strings (commands, expect
# patterns, send strings) with their resolved values. Used everywhere
# user-defined strings get expanded before being passed to a shell, the
# terminal, or asbru_conn.
#
# Supported tags (legacy syntax preserved):
#   <UUID> <NAME> <TITLE> <IP> <PORT> <USER> <PASS>     — built-in connection
#   <DATE_Y> <DATE_M> <DATE_D> <TIME_H> <TIME_M> <TIME_S>
#   <TIMESTAMP> <SOCKS5_PORT>
#   <GV:name>                                            — global variable
#   <V:N>                                                — session variable #N
#   <ENV:NAME>                                           — environment variable
#   <ASK:N>                                              — modal "enter value"
#   <ASK:label|opt1|opt2|...>                            — modal combo box
#   <ASK:label>                                          — modal "enter value"
#   <CMD:program args>                                   — shell command output
#   <CTRL_*:cmd> <TEE:var> <PIPE:cmd>                    — output redirection
#   \n \r \t                                             — escape sequences
#
# Security:
#   - <GV:> and <V:> values are scanned for shell metacharacters and
#     sanitized (backslash-escaped) before substitution.
#   - <CMD:> arguments are whitelist-validated against shell injection.
#   - $ENV{ASBRU_ENV_FOR_EXTERNAL} is structurally validated before being
#     used as a shell prefix.
###############################################################################

use strict;
use warnings;
use utf8;

use POSIX qw(strftime);

use PAC::Globals;
use PAC::Dialog;

our $VERSION = '0.1.0';

# Built-in tags resolved from the connection's environment hash.
my @LOCAL_VARS = qw(UUID SOCKS5_PORT TIMESTAMP DATE_Y DATE_M DATE_D
                    TIME_H TIME_M TIME_S NAME TITLE IP PORT USER PASS);

#-------------------------------------------------------------------------
# Public API — same call shape as legacy PACUtils::_subst / _substCFG.
#-------------------------------------------------------------------------

# subst($string, $cfg, $uuid, $uuid_tmp, $asbru_conn, $kpxc)
# In scalar context: returns expanded string.
# In list context:   returns ($expanded_string, \%output_meta).
sub subst {
    my $string     = shift;
    my $CFG        = shift;
    my $uuid       = shift;
    my $uuid_tmp   = shift;
    my $asbru_conn = shift;
    my $kpxc       = shift;

    my $ret  = $string;
    my %V    = ();
    my %out;
    my $pos  = -1;

    # Resolve built-in vars from the connection's environment, when uuid known.
    if (defined $uuid) {
        my $env = $$CFG{'environments'}{$uuid};
        return $string unless defined $env;

        $V{'UUID'}  = $uuid;
        $V{'NAME'}  = $env->{name};
        $V{'TITLE'} = $env->{title};
        $V{'IP'}    = $env->{ip};
        $V{'PORT'}  = $env->{port};
        if (($env->{'auth type'} // '') eq 'publickey') {
            $V{'USER'} = $env->{'passphrase user'};
            $V{'PASS'} = $env->{passphrase};
        } else {
            $V{'USER'} = $env->{user};
            $V{'PASS'} = $env->{pass};
        }

        my $running = PAC::Globals::running();
        my $socks   = PAC::Globals::socks5_ports();
        if (($env->{'method'} // '') =~ /ssh/i
            && $env->{'connection options'}{'randomSocksTunnel'}
            && defined $uuid_tmp
            && defined $socks->{$uuid_tmp})
        {
            $V{'SOCKS5_PORT'} = $socks->{$uuid_tmp};
        } else {
            $V{'SOCKS5_PORT'} = '';
        }
    }

    $V{'TIMESTAMP'} = time;
    @V{qw(DATE_Y DATE_M DATE_D TIME_H TIME_M TIME_S)}
        = split('_', strftime('%Y_%m_%d_%H_%M_%S', localtime));

    # Built-in tag substitution
    foreach my $var (@LOCAL_VARS) {
        if (defined $V{$var}) {
            while ($string =~ s/<$var>/$V{$var}/g) {}
            $ret = $string;
        }
    }

    # <GV:name> — global variables (shell-meta sanitized)
    while ($string =~ /<GV:(.+?)>/go) {
        my $var = $1;
        if (defined $$CFG{'defaults'}{'global variables'}{$var}) {
            my $val = $$CFG{'defaults'}{'global variables'}{$var}{'value'} // '';
            if ($val =~ /[`\$\(\)\{\};&|<>]/) {
                warn "WARNING: Global variable '$var' contains shell metacharacters - sanitizing\n";
                $val =~ s/([`\$\(\)\{\};&|<>])/\\$1/g;
            }
            $string =~ s/<GV:\Q$var\E>/$val/g;
            $ret = $string;
        }
    }

    # <V:N> — session variables (shell-meta sanitized)
    if (defined $uuid) {
        while ($string =~ /<V:(\d+?)>/go) {
            my $var = $1;
            if (defined $$CFG{'environments'}{$uuid}{'variables'}[$var]) {
                my $val = $$CFG{'environments'}{$uuid}{'variables'}[$var]{txt} // '';
                if ($val =~ /[`\$\(\)\{\};&|<>]/) {
                    warn "WARNING: Session variable #$var contains shell metacharacters - sanitizing\n";
                    $val =~ s/([`\$\(\)\{\};&|<>])/\\$1/g;
                }
                $string =~ s/<V:\Q$var\E>/$val/g;
                $ret = $string;
            }
        }
    }

    # <ENV:NAME> — environment variables (no shell-meta sanitization; the
    # caller is expected to know what's in their own env)
    while ($string =~ /<ENV:(.+?)>/go) {
        my $var = $1;
        if (defined $ENV{$var}) {
            my $val = $ENV{$var} // '';
            $string =~ s/<ENV:\Q$var\E>/$val/g;
            $ret = $string;
        }
    }

    # Honor escape sequences \n \r \t in multi-line command/send fields.
    $ret =~ s/\\n/\n/g;
    $ret =~ s/\\r/\r/g;
    $ret =~ s/\\t/\t/g;

    if (!$asbru_conn) {
        # <ASK:N> — numbered prompt
        while ($string =~ /<ASK:(\d+?)>/go) {
            my $var = $1;
            my $val = PAC::Dialog::_wEnterValue(
                undef, "<b>Variable substitution '$var'</b>", $string)
                // return undef;
            $string =~ s/<ASK:$var>/$val/g;
            $ret = $string;
        }

        # <ASK:label|opt1|opt2|...> — combo box
        while ($string =~ /<ASK:(.+?)\|(.+?)>/go) {
            my $desc = $1;
            my $var  = $2;
            my @list = split('\|', $var);
            ($ret, $pos) = PAC::Dialog::_wEnterValue(
                undef, '<b>Choose variable value:</b>', $desc, \@list);
            $string =~ s/<ASK:(.+?)\|(.+?)>/$ret/;
            $ret = $string;
        }

        # <ASK:label> — generic prompt
        while ($string =~ /<ASK:(.+?)>/go) {
            my $var = $1;
            my $val = PAC::Dialog::_wEnterValue(
                undef, '<b>Variable substitution</b>',
                "Please, enter a value for:'$var'")
                // return undef;
            $string =~ s/<ASK:\Q$var\E>/$val/g;
            $ret = $string;
        }

        # <CMD:program args> — execute and substitute output (whitelist-gated)
        while ($string =~ /<CMD:(.+?)>/go) {
            my $var = $1;
            # Whitelist: letters, digits, spaces, hyphens, underscores, dots,
            # forward slashes, colons, equals, commas, @, ~, plus
            if ($var !~ /^[\w\s\-\.\/\:=,\@~\+]+$/ || $var =~ /\beval\b/) {
                warn "WARNING: Blocked <CMD:$var> - contains disallowed characters\n";
                $string =~ s/<CMD:\Q$var\E>//g;
                $ret = $string;
                next;
            }
            # Validate ASBRU_ENV_FOR_EXTERNAL before splicing into a backtick.
            my $prefix = $ENV{'ASBRU_ENV_FOR_EXTERNAL'} // '';
            if ($prefix ne '' && $prefix !~ /^(?:[\w]+=[\w\/\.:,\-~]*\s*)+$/) {
                warn "WARNING: ASBRU_ENV_FOR_EXTERNAL contains suspicious content, ignoring\n";
                $prefix = '';
            }
            my $output = `$prefix $var 2>/dev/null`;
            chomp $output;
            if ($output =~ /\R/go) {
                $string =~ s/<CMD:\Q$var\E>/echo "$output"/g;
            } else {
                $string =~ s/<CMD:\Q$var\E>/$output/g;
            }
            $ret = $string;
        }

        # <CTRL_*:cmd> — record control-key handler, strip from string
        while ($string =~ /<CTRL_(.+?):(.+?)>/go) {
            my $ctrl = $1;
            my $cmd  = $2;
            $out{'ctrl'}{'ctrl'} = $ctrl;
            $out{'ctrl'}{'cmd'}  = $cmd;
            $string =~ s/<CTRL_$ctrl:$cmd>//g;
            $ret = $string;
        }

        # <TEE:var> — record tee target, strip
        while ($string =~ /<TEE:(.+)>/go) {
            my $var = $1;
            $out{'tee'} = $var;
            $string =~ s/<TEE:$var>//g;
            $ret = $string;
        }

        # <PIPE:cmd:prompt> — record pipe + prompt, strip
        while ($string =~ /<PIPE:(.+?):(.+?)>/go) {
            my $pipe   = $1;
            my $prompt = $2;
            push @{$out{'pipe'}}, $pipe;
            $out{'prompt'} = $prompt;
            $string =~ s/<PIPE:\Q$pipe\E:\Q$prompt>\E//g;
            $ret = $string;
        }
        # <PIPE:cmd> — record pipe only, strip
        while ($string =~ /<PIPE:(.+?)>/go) {
            my $var = $1;
            push @{$out{'pipe'}}, $var;
            $string =~ s/<PIPE:$var>//g;
            $ret = $string;
        }
    }

    # KeePassXC mask application
    if ($$CFG{'defaults'}{'keepass'}{'use_keepass'}) {
        if (!$asbru_conn) {
            $kpxc = PAC::Globals::funcs()->{_KEEPASS};
        }
        if (defined $kpxc) {
            $ret = $kpxc->applyMask($ret);
        }
    }

    return $ret if $asbru_conn;

    $out{'pos'} = $pos;
    return wantarray ? ($ret, \%out) : $ret;
}

# subst_cfg($cfg_subhash, $list)
# Bulk-edit helper: applies a hashref of {key => {change, regexp, value, match}}
# replacements onto the given config sub-hash. Used by the bulk-edit dialog.
sub subst_cfg {
    my $cfg  = shift;
    my $list = shift;

    foreach my $key (keys %{$cfg}) {
        next if $key =~ /^(variables|screenshots|local before|local connected|local after|expect|macros|terminal options)$/o;
        next unless defined $list->{$key};
        next unless $list->{$key}{'change'};

        if ($list->{$key}{'regexp'} // 0) {
            my $val = $list->{$key}{'value'};
            $cfg->{$key} =~ s/$list->{$key}{'match'}/$val/g;
        } else {
            $cfg->{$key} = $list->{$key}{'value'};
        }
    }

    if ($list->{'EXPECT:expect'} && $list->{'EXPECT:expect'}{'change'}) {
        foreach my $exp (@{$cfg->{'expect'}}) {
            if ($list->{'EXPECT:expect'}{'regexp'} // 0) {
                my $val = $list->{'EXPECT:expect'}{'value'};
                $exp->{'expect'} =~ s/$list->{'EXPECT:expect'}{'match'}/$val/g;
            } else {
                $exp->{'expect'} = $list->{'EXPECT:expect'}{'value'};
            }
        }
    }

    if ($list->{'EXPECT:send'} && $list->{'EXPECT:send'}{'change'}) {
        foreach my $exp (@{$cfg->{'expect'}}) {
            if ($list->{'EXPECT:send'}{'regexp'} // 0) {
                my $val = $list->{'EXPECT:send'}{'value'};
                $exp->{'send'} =~ s/$list->{'EXPECT:send'}{'match'}/$val/g;
            } else {
                $exp->{'send'} = $list->{'EXPECT:send'}{'value'};
            }
        }
    }

    if ($list->{'__delete_hidden_fields__'} // 0) {
        foreach my $hash (@{$cfg->{'expect'}}) {
            $hash->{'send'} = '' if $hash->{'hidden'};
        }
    }

    return 1;
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Subst — template-variable substitution engine for asbru-plus

=head1 SYNOPSIS

    use PAC::Subst;

    my $cmd = PAC::Subst::subst('ssh <USER>@<IP> -p <PORT>',
                                $cfg, $uuid);
    # → "ssh alice\@10.0.0.1 -p 22"

    my ($cmd2, $meta) = PAC::Subst::subst('echo hi <TEE:my-out>',
                                          $cfg, $uuid);
    # $meta->{tee} = 'my-out'; $cmd2 has the <TEE:...> stripped

=head1 DESCRIPTION

Pulls C<_subst> and C<_substCFG> out of PACUtils.pm into a focused
module. Same signature, same return semantics, same supported tag
syntax — call sites work unchanged via the proxies in PACUtils.

The module supports four classes of tag:

=over

=item *

B<Built-in connection vars> — C<E<lt>UUIDE<gt>>, C<E<lt>NAMEE<gt>>,
C<E<lt>IPE<gt>>, etc.

=item *

B<User vars> — C<E<lt>GV:nameE<gt>> (global), C<E<lt>V:NE<gt>>
(per-session), C<E<lt>ENV:NAMEE<gt>> (process env)

=item *

B<Interactive prompts> — C<E<lt>ASK:NE<gt>>, C<E<lt>ASK:label|optE<gt>>,
C<E<lt>ASK:labelE<gt>>

=item *

B<Side-effecting> — C<E<lt>CMD:argsE<gt>> (whitelist-gated shell exec),
C<E<lt>CTRL_X:cmdE<gt>>, C<E<lt>TEE:varE<gt>>, C<E<lt>PIPE:cmdE<gt>>

=back

Plus C<\n>/C<\r>/C<\t> escape sequences and KeePassXC mask
application when C<defaults.keepass.use_keepass> is set.

=head1 SECURITY

User-controlled values for C<E<lt>GV:E<gt>> and C<E<lt>V:E<gt>> are
scanned for shell metacharacters and backslash-escaped before
substitution to prevent command injection. C<E<lt>CMD:E<gt>> arguments
are whitelist-validated against an allow-list of safe characters and
the C<eval> keyword is rejected. The C<ASBRU_ENV_FOR_EXTERNAL> env
var is structurally validated (only C<KEY=VALUE> pairs) before being
used as a shell prefix.

=head1 PUBLIC API

=over

=item subst($string, $cfg, $uuid, $uuid_tmp, $asbru_conn, $kpxc)

Returns the expanded string. In list context returns
C<($expanded_string, \%output_meta)> where C<%output_meta> contains
any C<E<lt>CTRL_E<gt>>/C<E<lt>TEEE<gt>>/C<E<lt>PIPEE<gt>> side-channel
data. C<$asbru_conn> is a flag suppressing the interactive
C<E<lt>ASKE<gt>> and shell-exec C<E<lt>CMDE<gt>> branches when called
from the helper process.

=item subst_cfg($cfg_subhash, $list)

Bulk-edit helper: applies a hashref of replacement specs to the given
sub-hash. Used by the bulk-edit dialog.

=back

=head1 SEE ALSO

L<PAC::Dialog/_wEnterValue>, L<PAC::Globals>, the legacy
C<PACUtils::_subst> proxy.

=cut
