#!/usr/bin/perl
# t/09-subst.t — Tests for _subst() variable substitution in PACUtils.pm
# Tests parts that work without a live GUI: ENV vars, GV vars, session fields
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

use lib "$RealBin/../lib/ex";
use lib "$RealBin/../lib";
use lib "$RealBin/lib";

BEGIN {
    my @stubs = qw(Gtk3 Gtk3::Gdk Glib Glib::IO Glib::Object::Introspection
                   Pango Cairo SortedTreeStore Gnome2::Wnck Vte2ext);
    for my $mod (@stubs) {
        (my $file = $mod) =~ s|::|/|g;
        $INC{"$file.pm"} //= 1;
    }
    package Gtk3;
    sub import {} sub init { 1 }
    sub events_pending { 0 } sub main_iteration { 0 } sub main_iteration_do { 0 }
    sub main_quit {} sub main {} sub TRUE { 1 } sub FALSE { 0 }
    package Gtk3::Gdk; sub import {} our $AUTOLOAD;
    sub AUTOLOAD { return if $AUTOLOAD =~ /::DESTROY$/; bless {}, 'Gtk3::Gdk' } sub DESTROY {}
    package Gtk3::Gdk::Pixbuf; sub import {} our $AUTOLOAD;
    sub new { bless {}, 'Gtk3::Gdk::Pixbuf' }
    sub new_from_file { bless {}, 'Gtk3::Gdk::Pixbuf' }
    sub new_from_file_at_scale { bless {}, 'Gtk3::Gdk::Pixbuf' }
    sub AUTOLOAD { return if $AUTOLOAD =~ /::DESTROY$/; bless {}, 'Gtk3::Gdk::Pixbuf' } sub DESTROY {}
    package Glib; sub import {}
    package Glib::IO; sub import {} sub add_watch { 0 }
    package Glib::Object::Introspection; sub setup { 1 } sub import {}
    package Pango; sub import {}
    package Cairo; sub import {}
    package SortedTreeStore; sub new { bless {}, shift } sub import {}

    # Stub PACMain globals referenced by _subst()
    package PACMain;
    our %RUNNING  = ();
    our %FUNCS    = ();
    our %SOCKS5PORTS = ();
    package main;
}

local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ /redefined/i };
eval { require PACUtils } or BAIL_OUT("Cannot load PACUtils: $@");

# Helper: minimal CFG for a session
sub cfg_for {
    my (%s) = @_;
    my $uuid = $s{uuid} // 'u001';
    return ({
        defaults => {
            'global variables' => $s{gv} // {},
        },
        environments => {
            $uuid => {
                name       => $s{name}    // 'MyServer',
                title      => $s{title}   // 'MyTitle',
                ip         => $s{ip}      // '192.168.1.1',
                port       => $s{port}    // '22',
                user       => $s{user}    // 'admin',
                pass       => $s{pass}    // 'secret',
                'auth type'=> $s{auth}    // 'userpass',
                'passphrase user' => $s{ppk_user} // '',
                passphrase => $s{ppk_pass} // '',
                variables  => $s{vars}    // [],
                method     => $s{method}  // 'ssh',
                'connection options' => { randomSocksTunnel => 0 },
            },
        },
    }, $uuid);
}

# ── <IP>, <PORT>, <USER>, <PASS> substitution ────────────────────────────────

subtest 'session field substitutions' => sub {
    my ($cfg, $uuid) = cfg_for(ip => '10.0.0.1', port => '2222',
                                user => 'bob', pass => 'p@ss');

    is(PACUtils::_subst('<IP>',   $cfg, $uuid), '10.0.0.1',  '<IP> replaced');
    is(PACUtils::_subst('<PORT>', $cfg, $uuid), '2222',       '<PORT> replaced');
    is(PACUtils::_subst('<USER>', $cfg, $uuid), 'bob',        '<USER> replaced');
    is(PACUtils::_subst('<PASS>', $cfg, $uuid), 'p@ss',       '<PASS> replaced');
    is(PACUtils::_subst('<NAME>', $cfg, $uuid), 'MyServer',   '<NAME> replaced');
};

# ── publickey auth: USER/PASS come from passphrase fields ────────────────────

subtest 'publickey auth — USER/PASS from passphrase fields' => sub {
    my ($cfg, $uuid) = cfg_for(auth => 'publickey',
                                ppk_user => 'keyuser', ppk_pass => 'keyphrase',
                                user => 'ignored', pass => 'ignored');
    is(PACUtils::_subst('<USER>', $cfg, $uuid), 'keyuser',   '<USER> from passphrase user');
    is(PACUtils::_subst('<PASS>', $cfg, $uuid), 'keyphrase', '<PASS> from passphrase');
};

# ── Multiple substitutions in one string ─────────────────────────────────────

subtest 'multiple substitutions in one string' => sub {
    my ($cfg, $uuid) = cfg_for(user => 'alice', ip => '1.2.3.4', port => '22');
    my $result = PACUtils::_subst('ssh -p <PORT> <USER>@<IP>', $cfg, $uuid);
    is($result, 'ssh -p 22 alice@1.2.3.4', 'compound substitution correct');
};

# ── Unknown UUID returns original string ─────────────────────────────────────

subtest 'unknown UUID returns original string' => sub {
    my ($cfg, $uuid) = cfg_for();
    my $s = PACUtils::_subst('<IP>', $cfg, 'no-such-uuid');
    is($s, '<IP>', 'unknown UUID: string returned as-is');
};

# ── No UUID — timestamp vars substituted, session vars not ───────────────────

subtest 'no UUID — only timestamp vars substituted' => sub {
    my ($cfg, $uuid) = cfg_for(ip => '1.2.3.4');
    my $result = PACUtils::_subst('<IP>', $cfg, undef);
    # Without UUID, <IP> cannot be resolved — stays as-is
    is($result, '<IP>', '<IP> not substituted without UUID');

    # <TIMESTAMP> should be a positive integer
    my $ts = PACUtils::_subst('<TIMESTAMP>', $cfg, undef);
    like($ts, qr/^\d+$/, '<TIMESTAMP> is a numeric epoch');
    ok($ts > 1_000_000_000, '<TIMESTAMP> looks like a real epoch');
};

# ── <ENV:VAR> substitution ────────────────────────────────────────────────────

subtest '<ENV:VAR> substitution' => sub {
    local $ENV{_ASBRU_TEST_VAR} = 'hello_from_env';
    my ($cfg, $uuid) = cfg_for();
    my $result = PACUtils::_subst('<ENV:_ASBRU_TEST_VAR>', $cfg, $uuid);
    is($result, 'hello_from_env', '<ENV:VAR> substituted from environment');
};

subtest '<ENV:VAR> undefined var stays as-is' => sub {
    delete $ENV{_ASBRU_UNDEFINED_VAR};
    my ($cfg, $uuid) = cfg_for();
    my $result = PACUtils::_subst('<ENV:_ASBRU_UNDEFINED_VAR>', $cfg, $uuid);
    is($result, '<ENV:_ASBRU_UNDEFINED_VAR>', 'undefined ENV var not substituted');
};

# ── <GV:VAR> global variable substitution ────────────────────────────────────

subtest '<GV:name> global variable substitution' => sub {
    my ($cfg, $uuid) = cfg_for(gv => {
        'PROD_HOST' => { value => 'prod.example.com', hidden => '0' },
    });
    my $result = PACUtils::_subst('<GV:PROD_HOST>', $cfg, $uuid);
    is($result, 'prod.example.com', '<GV:name> substituted');
};

subtest '<GV:name> undefined global var stays as-is' => sub {
    my ($cfg, $uuid) = cfg_for(gv => {});
    my $result = PACUtils::_subst('<GV:NO_SUCH_VAR>', $cfg, $uuid);
    is($result, '<GV:NO_SUCH_VAR>', 'undefined GV stays as-is');
};

# ── <V:N> per-session variable substitution ──────────────────────────────────

subtest '<V:N> per-session variable substitution' => sub {
    my ($cfg, $uuid) = cfg_for(vars => [
        { txt => 'value_zero', hide => '0' },
        { txt => 'value_one',  hide => '0' },
    ]);
    is(PACUtils::_subst('<V:0>', $cfg, $uuid), 'value_zero', '<V:0> substituted');
    is(PACUtils::_subst('<V:1>', $cfg, $uuid), 'value_one',  '<V:1> substituted');
};

# ── String without any tokens is returned unchanged ──────────────────────────

subtest 'string with no tokens unchanged' => sub {
    my ($cfg, $uuid) = cfg_for();
    is(PACUtils::_subst('no tokens here', $cfg, $uuid), 'no tokens here',
        'plain string not modified');
    is(PACUtils::_subst('', $cfg, $uuid), '', 'empty string stays empty');
};

# ── <DATE_*> and <TIME_*> substitutions are numeric ──────────────────────────

subtest 'date/time substitutions are numeric' => sub {
    my ($cfg, $uuid) = cfg_for();
    for my $var (qw(DATE_Y DATE_M DATE_D TIME_H TIME_M TIME_S)) {
        my $val = PACUtils::_subst("<$var>", $cfg, $uuid);
        like($val, qr/^\d+$/, "<$var> is numeric");
    }
};

done_testing();
