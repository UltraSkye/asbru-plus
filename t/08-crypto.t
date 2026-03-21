#!/usr/bin/perl
# t/08-crypto.t — Tests for _cipherCFG / _decipherCFG encrypt-decrypt roundtrip
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
    package main;
}

local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ /redefined/i };
eval { require PACUtils } or BAIL_OUT("Cannot load PACUtils: $@");

# Helper: build a minimal cfg structure as _cipherCFG / _decipherCFG expect
sub make_cfg {
    my (%args) = @_;
    my $uuid = $args{uuid} // 'test-uuid-001';
    return {
        defaults => {
            'sudo password' => $args{sudo_pass} // '',
            'global variables' => $args{gv} // {},
            'keepass' => $args{keepass},   # may be undef
        },
        environments => {
            $uuid => {
                '_is_group'  => 0,
                pass         => $args{pass}       // '',
                passphrase   => $args{passphrase} // '',
                expect       => $args{expect}     // [],
                variables    => $args{vars}        // [],
            },
        },
    };
}

# ── Basic roundtrip ───────────────────────────────────────────────────────────

subtest 'cipher/decipher roundtrip — simple passwords' => sub {
    my $uuid = 'uuid-round-001';
    my $cfg = make_cfg(uuid => $uuid, pass => 'secret123', sudo_pass => 'root!pass');

    PACUtils::_cipherCFG($cfg);

    # After encryption: values must differ from plaintext
    isnt($cfg->{environments}{$uuid}{pass}, 'secret123',
        'session pass is encrypted (not plaintext)');
    isnt($cfg->{defaults}{'sudo password'}, 'root!pass',
        'sudo password is encrypted');

    PACUtils::_decipherCFG($cfg);

    is($cfg->{environments}{$uuid}{pass}, 'secret123',
        'session pass decrypted correctly');
    is($cfg->{defaults}{'sudo password'}, 'root!pass',
        'sudo password decrypted correctly');
};

# ── Special characters survive roundtrip ─────────────────────────────────────

subtest 'cipher/decipher roundtrip — special chars in password' => sub {
    my $uuid = 'uuid-special-001';
    for my $pass ('', 'P@ss!#$%^&*()-=[]{}|;:<>,.?/~`',
                  'пароль', 'パスワード', "tab\there", "new\nline") {
        my $cfg = make_cfg(uuid => $uuid, pass => $pass);
        PACUtils::_cipherCFG($cfg);
        PACUtils::_decipherCFG($cfg);
        is($cfg->{environments}{$uuid}{pass}, $pass,
            "roundtrip: " . (length($pass) ? substr($pass,0,20) : '(empty)'));
    }
};

# ── Passphrase (public key auth) roundtrip ────────────────────────────────────

subtest 'cipher/decipher roundtrip — passphrase field' => sub {
    my $uuid = 'uuid-ppk-001';
    my $cfg = make_cfg(uuid => $uuid, passphrase => 'my-key-passphrase!');
    PACUtils::_cipherCFG($cfg);
    isnt($cfg->{environments}{$uuid}{passphrase}, 'my-key-passphrase!',
        'passphrase is encrypted');
    PACUtils::_decipherCFG($cfg);
    is($cfg->{environments}{$uuid}{passphrase}, 'my-key-passphrase!',
        'passphrase decrypted correctly');
};

# ── Encrypted value is hex string ────────────────────────────────────────────

subtest 'encrypted value is hex string' => sub {
    my $uuid = 'uuid-hex-001';
    my $cfg = make_cfg(uuid => $uuid, pass => 'testpassword');
    PACUtils::_cipherCFG($cfg);
    like($cfg->{environments}{$uuid}{pass}, qr/^[0-9a-f]+$/i,
        'encrypted pass is a hex string');
};

# ── Groups are handled (no pass field) ───────────────────────────────────────

subtest 'group environments not encrypted' => sub {
    my $cfg = {
        defaults => { 'sudo password' => '', 'global variables' => {} },
        environments => {
            'group-uuid' => { '_is_group' => 1, pass => 'should-be-deleted' },
            'real-uuid'  => { '_is_group' => 0, pass => 'realpass',
                              passphrase => '', expect => [], variables => [] },
        },
    };
    PACUtils::_cipherCFG($cfg);
    ok(!defined $cfg->{environments}{'group-uuid'}{pass},
        'group pass field deleted after cipher');
    PACUtils::_decipherCFG($cfg);
    ok(!defined $cfg->{environments}{'group-uuid'}{pass},
        'group pass field still absent after decipher');
    is($cfg->{environments}{'real-uuid'}{pass}, 'realpass',
        'real session pass decrypted correctly');
};

# ── Hidden global variables roundtrip ────────────────────────────────────────

subtest 'cipher/decipher — hidden global variables' => sub {
    my $cfg = make_cfg(gv => {
        'SECRET_TOKEN' => { hidden => '1', value => 'tok3n_v@lue' },
        'PUBLIC_VAR'   => { hidden => '0', value => 'plain_value' },
    });
    PACUtils::_cipherCFG($cfg);
    isnt($cfg->{defaults}{'global variables'}{'SECRET_TOKEN'}{value}, 'tok3n_v@lue',
        'hidden global var encrypted');
    is($cfg->{defaults}{'global variables'}{'PUBLIC_VAR'}{value}, 'plain_value',
        'non-hidden global var NOT encrypted');
    PACUtils::_decipherCFG($cfg);
    is($cfg->{defaults}{'global variables'}{'SECRET_TOKEN'}{value}, 'tok3n_v@lue',
        'hidden global var decrypted correctly');
};

# ── KeePass password roundtrip ───────────────────────────────────────────────

subtest 'cipher/decipher — keepass password' => sub {
    my $cfg = make_cfg(keepass => { password => 'master-pass!' });
    PACUtils::_cipherCFG($cfg);
    isnt($cfg->{defaults}{keepass}{password}, 'master-pass!',
        'keepass password encrypted');
    PACUtils::_decipherCFG($cfg);
    is($cfg->{defaults}{keepass}{password}, 'master-pass!',
        'keepass password decrypted correctly');
};

# ── Hidden expect entries roundtrip ──────────────────────────────────────────

subtest 'cipher/decipher — hidden expect entries' => sub {
    my $uuid = 'uuid-expect-001';
    my $cfg = make_cfg(
        uuid   => $uuid,
        pass   => '',
        expect => [
            { hidden => '1', send => 'secret_response', expect => 'password:' },
            { hidden => '0', send => 'plain_response',  expect => 'login:'    },
        ],
    );
    PACUtils::_cipherCFG($cfg);
    isnt($cfg->{environments}{$uuid}{expect}[0]{send}, 'secret_response',
        'hidden expect entry encrypted');
    is($cfg->{environments}{$uuid}{expect}[1]{send}, 'plain_response',
        'non-hidden expect entry NOT encrypted');
    PACUtils::_decipherCFG($cfg);
    is($cfg->{environments}{$uuid}{expect}[0]{send}, 'secret_response',
        'hidden expect entry decrypted correctly');
};

# ── single_uuid mode only decrypts one session ───────────────────────────────

subtest 'decipher with single_uuid only touches target session' => sub {
    my $cfg = {
        defaults => { 'sudo password' => '', 'global variables' => {} },
        environments => {
            'uuid-A' => { '_is_group' => 0, pass => 'passA', passphrase => '',
                          expect => [], variables => [] },
            'uuid-B' => { '_is_group' => 0, pass => 'passB', passphrase => '',
                          expect => [], variables => [] },
        },
    };
    PACUtils::_cipherCFG($cfg);
    my $enc_b = $cfg->{environments}{'uuid-B'}{pass};

    PACUtils::_decipherCFG($cfg, 'uuid-A');  # only decipher uuid-A

    is($cfg->{environments}{'uuid-A'}{pass}, 'passA',
        'uuid-A decrypted when targeted');
    is($cfg->{environments}{'uuid-B'}{pass}, $enc_b,
        'uuid-B remains encrypted when not targeted');
};

done_testing();
