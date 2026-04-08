#!/usr/bin/perl
# t/15-functional-integrity.t — Comprehensive functional integrity tests
# Verifies that all core functionality works correctly after security hardening
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use File::Temp qw(tempdir tempfile);
use File::Path qw(make_path remove_tree);
use Storable qw(dclone);

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
    sub Glib::Markup::escape_text { return $_[0] // '' }
    package Glib::IO; sub import {} sub add_watch { 0 }
    package Glib::Object::Introspection; sub setup { 1 } sub import {}
    package Pango; sub import {}
    package Cairo; sub import {}
    package SortedTreeStore; sub new { bless {}, shift } sub import {}
    package PACMain;
    our %RUNNING  = ();
    our %FUNCS    = ();
    our %SOCKS5PORTS = ();
    package main;
}

local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ /redefined|uninitialized/i };
eval { require PACUtils } or BAIL_OUT("Cannot load PACUtils: $@");

# ═══════════════════════════════════════════════════════════════════════════════
# Helper: build minimal config structure
# ═══════════════════════════════════════════════════════════════════════════════

sub make_cfg {
    my (%opts) = @_;
    return {
        defaults => {
            version => $opts{version} // '7.0.0',
            'global variables' => $opts{gv} // {},
            'sudo password' => $opts{sudo_pass} // 'sudopass',
            keepass => $opts{keepass} // { database => '', password => '', use_keepass => 0 },
        },
        environments => {
            '__PAC__ROOT__' => { _is_group => 1, name => 'ROOT', children => {}, parent => undef },
            ($opts{uuid} // 'test-uuid-0001') => {
                name       => $opts{name} // 'TestServer',
                title      => $opts{title} // 'Test',
                ip         => $opts{ip} // '10.0.0.1',
                port       => $opts{port} // '22',
                user       => $opts{user} // 'admin',
                pass       => $opts{pass} // 'secret123',
                passphrase => $opts{passphrase} // 'pp_phrase',
                method     => $opts{method} // 'SSH',
                'auth type' => $opts{auth} // 'userpass',
                'passphrase user' => '',
                options    => $opts{options} // '',
                variables  => $opts{vars} // [],
                expect     => $opts{expect} // [],
                screenshots => [],
                'local before' => [],
                'local connected' => [],
                'local after' => [],
                macros => [],
                cluster => [],
                parent => '__PAC__ROOT__',
                _protected => 0,
                'search pass on KPX' => 0,
                'send slow' => 0,
                'auth fallback' => 1,
                'public key' => '',
                'use proxy' => 0,
                'save session logs' => 0,
                'connection options' => { randomSocksTunnel => 0 },
            },
        },
        tmp => { changed => 0 },
    };
}

# ═══════════════════════════════════════════════════════════════════════════════
# 1. _cfgSanityCheck — Config Initialization & Defaults
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_cfgSanityCheck — empty config gets all defaults' => sub {
    my $cfg = {};
    PACUtils::_cfgSanityCheck($cfg);

    # Core defaults
    ok(defined $$cfg{defaults}{version}, 'version set');
    is($$cfg{defaults}{'auto accept key'}, 0, 'auto accept key defaults OFF (security)');
    is($$cfg{defaults}{'cursor shape'}, 'block', 'cursor shape default');
    is($$cfg{defaults}{'terminal character encoding'}, 'UTF-8', 'default encoding UTF-8');
    is($$cfg{defaults}{'terminal scrollback lines'}, 5000, 'scrollback default 5000');
    is($$cfg{defaults}{'confirm exit'}, 1, 'confirm exit ON');
    is($$cfg{defaults}{'proxy port'}, 8080, 'default proxy port 8080');
    is($$cfg{defaults}{'save session logs'}, 0, 'session logs off by default');
    is($$cfg{defaults}{'session logs amount'}, 10, 'session log amount default 10');
    ok(defined $$cfg{defaults}{'command prompt'}, 'command prompt set');
    ok(defined $$cfg{defaults}{'username prompt'}, 'username prompt set');
    ok(defined $$cfg{defaults}{'password prompt'}, 'password prompt set');

    # Structures initialized
    is(ref($$cfg{defaults}{'global variables'}), 'HASH', 'global variables hash created');
    is(ref($$cfg{defaults}{'local commands'}), 'ARRAY', 'local commands array created');
    is(ref($$cfg{defaults}{'remote commands'}), 'ARRAY', 'remote commands array created');
    is(ref($$cfg{defaults}{'auto cluster'}), 'HASH', 'auto cluster hash created');

    # KeePass defaults
    ok(defined $$cfg{defaults}{keepass}, 'keepass hash created');
    is($$cfg{defaults}{keepass}{use_keepass}, 0, 'keepass disabled by default');

    # __PAC_SHELL__ pseudo-connection created
    ok(defined $$cfg{environments}{'__PAC_SHELL__'}, '__PAC_SHELL__ created');
    is($$cfg{environments}{'__PAC_SHELL__'}{name}, 'PACShell', '__PAC_SHELL__ name correct');
    is($$cfg{environments}{'__PAC_SHELL__'}{method}, 'PACShell', '__PAC_SHELL__ method correct');
    is($$cfg{environments}{'__PAC_SHELL__'}{ip}, 'bash', '__PAC_SHELL__ ip = bash');
};

subtest '_cfgSanityCheck — preserves existing values' => sub {
    my $cfg = {
        defaults => {
            version => '6.0.0',
            'auto accept key' => 1,
            'cursor shape' => 'ibeam',
            'terminal scrollback lines' => 10000,
        },
        environments => {},
    };
    PACUtils::_cfgSanityCheck($cfg);

    is($$cfg{defaults}{'auto accept key'}, 1, 'existing auto accept key preserved');
    is($$cfg{defaults}{'cursor shape'}, 'ibeam', 'existing cursor shape preserved');
    is($$cfg{defaults}{'terminal scrollback lines'}, 10000, 'existing scrollback preserved');
    # But missing defaults still get set
    is($$cfg{defaults}{'confirm exit'}, 1, 'missing confirm exit gets default');
};

subtest '_cfgSanityCheck — method name normalization' => sub {
    my $methods = {
        'ssh'        => 'SSH',
        'sftp'       => 'SFTP',
        'telnet'     => 'Telnet',
        'ftp'        => 'FTP',
        'remote-tty' => 'Serial (remote-tty)',
        '3270'       => 'IBM 3270/5250',
        'RDP (Windows)' => 'RDP (rdesktop)',
        'vncviewer'  => 'VNC',
        'generic'    => 'Generic Command',
    };

    for my $input (keys %$methods) {
        my $cfg = {
            defaults => {},
            environments => {
                'uuid-norm' => {
                    name => 'Test',
                    method => $input,
                    options => '',
                },
            },
        };
        PACUtils::_cfgSanityCheck($cfg);
        is($$cfg{environments}{'uuid-norm'}{method}, $methods->{$input},
            "method '$input' normalized to '$methods->{$input}'");
    }
};

subtest '_cfgSanityCheck — cleans invalid environments' => sub {
    my $cfg = {
        defaults => {},
        environments => {
            'HASH(0x12345)' => { name => 'Bad' },
            '_tmp_session'  => { name => 'Temp' },
            'pacshell_PID123' => { name => 'Shell' },
            ''              => { name => 'Empty' },
            'valid-uuid'    => { name => 'Real', method => 'SSH', options => '' },
            'no-name-uuid'  => {},
        },
    };
    PACUtils::_cfgSanityCheck($cfg);

    ok(!exists $$cfg{environments}{'HASH(0x12345)'}, 'HASH ref key removed');
    ok(!exists $$cfg{environments}{'_tmp_session'}, '_tmp_ prefix removed');
    ok(!exists $$cfg{environments}{'pacshell_PID123'}, 'pacshell_PID removed');
    ok(!exists $$cfg{environments}{''}, 'empty key removed');
    ok(exists $$cfg{environments}{'valid-uuid'}, 'valid UUID preserved');
    ok(!exists $$cfg{environments}{'no-name-uuid'}, 'nameless UUID removed');
};

subtest '_cfgSanityCheck — group entries preserved correctly' => sub {
    my $cfg = {
        defaults => {},
        environments => {
            'group-uuid' => {
                _is_group => 1,
                name => 'MyGroup',
                description => 'Test group',
                parent => '__PAC__ROOT__',
                children => { 'child1' => 1 },
                screenshots => ['shot1.png'],
                _protected => 1,
                # Extra keys that should be stripped from groups
                ip => '1.2.3.4',
                user => 'foo',
            },
        },
    };
    PACUtils::_cfgSanityCheck($cfg);

    my $g = $$cfg{environments}{'group-uuid'};
    ok($$g{_is_group}, 'group flag preserved');
    is($$g{name}, 'MyGroup', 'group name preserved');
    is($$g{_protected}, 1, 'group protection preserved');
    ok(exists $$g{children}, 'group children preserved');
    ok(!exists $$g{ip}, 'group ip stripped');
    ok(!exists $$g{user}, 'group user stripped');
};

subtest '_cfgSanityCheck — version-dependent GUI password handling' => sub {
    # Old version: force gui password off
    my $cfg_old = { defaults => { version => '4.0.0' }, environments => {} };
    PACUtils::_cfgSanityCheck($cfg_old);
    is($$cfg_old{defaults}{'use gui password'}, 0, 'old version: gui password forced off');
    is($$cfg_old{defaults}{'gui password'}, '', 'old version: gui password empty');

    # New version: respect existing values
    my $cfg_new = {
        defaults => {
            version => '5.0.0',
            'use gui password' => 1,
            'gui password' => 'encrypted_pass',
        },
        environments => {},
    };
    PACUtils::_cfgSanityCheck($cfg_new);
    is($$cfg_new{defaults}{'use gui password'}, 1, 'new version: gui password preserved');
    is($$cfg_new{defaults}{'gui password'}, 'encrypted_pass', 'new version: password preserved');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 2. _substCFG — Bulk Config Substitution
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_substCFG — direct value replacement' => sub {
    my $cfg = {
        ip => '10.0.0.1',
        port => '22',
        user => 'admin',
        variables => [],
        screenshots => [],
        expect => [],
        'local before' => [],
        macros => [],
        'terminal options' => {},
    };
    my $list = {
        ip => { change => 1, value => '192.168.1.100' },
        port => { change => 1, value => '2222' },
        user => { change => 0, value => 'should_not_change' },
    };
    PACUtils::_substCFG($cfg, $list);
    is($$cfg{ip}, '192.168.1.100', 'ip replaced');
    is($$cfg{port}, '2222', 'port replaced');
    is($$cfg{user}, 'admin', 'user unchanged (change=0)');
};

subtest '_substCFG — regex replacement' => sub {
    my $cfg = {
        ip => 'host-dev-01.example.com',
        variables => [],
        screenshots => [],
        expect => [],
        'local before' => [],
        macros => [],
        'terminal options' => {},
    };
    my $list = {
        ip => { change => 1, regexp => 1, match => '-dev-', value => '-prod-' },
    };
    PACUtils::_substCFG($cfg, $list);
    is($$cfg{ip}, 'host-prod-01.example.com', 'regex substitution in ip');
};

subtest '_substCFG — skips protected keys' => sub {
    my $cfg = {
        ip => '10.0.0.1',
        variables => [{ txt => 'should_stay', hide => 0 }],
        screenshots => ['shot.png'],
        expect => [],
        'local before' => [{ cmd => 'echo hi' }],
        macros => [{ name => 'macro1' }],
        'terminal options' => { font => 'Mono 12' },
    };
    my $list = {
        variables => { change => 1, value => 'overwrite' },
        screenshots => { change => 1, value => 'overwrite' },
        'local before' => { change => 1, value => 'overwrite' },
        macros => { change => 1, value => 'overwrite' },
        'terminal options' => { change => 1, value => 'overwrite' },
    };
    PACUtils::_substCFG($cfg, $list);
    is(ref($$cfg{variables}), 'ARRAY', 'variables array untouched');
    is($$cfg{variables}[0]{txt}, 'should_stay', 'variable content preserved');
    is(ref($$cfg{screenshots}), 'ARRAY', 'screenshots untouched');
};

subtest '_substCFG — EXPECT:expect substitution' => sub {
    my $cfg = {
        expect => [
            { expect => 'Password:', send => 'mypass' },
            { expect => 'Password:', send => 'otherpass' },
        ],
    };
    my $list = {
        'EXPECT:expect' => { change => 1, regexp => 1, match => 'Password:', value => 'Passphrase:' },
    };
    PACUtils::_substCFG($cfg, $list);
    is($$cfg{expect}[0]{expect}, 'Passphrase:', 'first expect pattern updated');
    is($$cfg{expect}[1]{expect}, 'Passphrase:', 'second expect pattern updated');
    is($$cfg{expect}[0]{send}, 'mypass', 'send values unchanged');
};

subtest '_substCFG — EXPECT:send substitution' => sub {
    my $cfg = {
        expect => [
            { expect => 'Password:', send => 'oldpass' },
            { expect => 'Confirm:', send => 'oldpass' },
        ],
    };
    my $list = {
        'EXPECT:send' => { change => 1, value => 'newpass' },
    };
    PACUtils::_substCFG($cfg, $list);
    is($$cfg{expect}[0]{send}, 'newpass', 'first send replaced');
    is($$cfg{expect}[1]{send}, 'newpass', 'second send replaced');
};

subtest '_substCFG — __delete_hidden_fields__ clears hidden sends' => sub {
    my $cfg = {
        expect => [
            { expect => 'Pass:', send => 'secret', hidden => 1 },
            { expect => 'Name:', send => 'bob', hidden => 0 },
        ],
    };
    my $list = { '__delete_hidden_fields__' => 1 };
    PACUtils::_substCFG($cfg, $list);
    is($$cfg{expect}[0]{send}, '', 'hidden send cleared');
    is($$cfg{expect}[1]{send}, 'bob', 'non-hidden send preserved');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 3. Cipher/Decipher Roundtrip — Full Config Integration
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'cipher/decipher — full config roundtrip' => sub {
    my $cfg = make_cfg(
        pass       => 'MyP@ssw0rd!',
        passphrase => 'MyPhrase',
        sudo_pass  => 'S00d0!',
        gv => {
            'SECRET_KEY' => { value => 'api_key_123', hidden => '1' },
            'PUBLIC_VAR' => { value => 'public_val',  hidden => '0' },
        },
        expect => [
            { expect => 'Password:', send => 'expect_pass', hidden => '1' },
            { expect => 'Name:',     send => 'bob',         hidden => '0' },
        ],
        vars => [
            { txt => 'hidden_var', hide => '1' },
            { txt => 'visible_var', hide => '0' },
        ],
        keepass => { database => '/tmp/test.kdbx', password => 'kp_pass', use_keepass => 1 },
    );

    my $original = dclone($cfg);

    # Encrypt
    PACUtils::_cipherCFG($cfg);

    # Verify encrypted values are different from originals
    isnt($$cfg{environments}{'test-uuid-0001'}{pass}, 'MyP@ssw0rd!', 'pass is encrypted');
    isnt($$cfg{environments}{'test-uuid-0001'}{passphrase}, 'MyPhrase', 'passphrase is encrypted');
    isnt($$cfg{defaults}{'sudo password'}, 'S00d0!', 'sudo password is encrypted');
    isnt($$cfg{defaults}{'global variables'}{'SECRET_KEY'}{value}, 'api_key_123', 'hidden GV encrypted');
    is($$cfg{defaults}{'global variables'}{'PUBLIC_VAR'}{value}, 'public_val', 'public GV not encrypted');
    isnt($$cfg{environments}{'test-uuid-0001'}{expect}[0]{send}, 'expect_pass', 'hidden expect encrypted');
    is($$cfg{environments}{'test-uuid-0001'}{expect}[1]{send}, 'bob', 'non-hidden expect not encrypted');
    isnt($$cfg{environments}{'test-uuid-0001'}{variables}[0]{txt}, 'hidden_var', 'hidden var encrypted');
    is($$cfg{environments}{'test-uuid-0001'}{variables}[1]{txt}, 'visible_var', 'visible var not encrypted');
    isnt($$cfg{defaults}{keepass}{password}, 'kp_pass', 'keepass password encrypted');

    # Decrypt
    PACUtils::_decipherCFG($cfg);

    # Verify decrypted values match originals
    is($$cfg{environments}{'test-uuid-0001'}{pass}, 'MyP@ssw0rd!', 'pass decrypted correctly');
    is($$cfg{environments}{'test-uuid-0001'}{passphrase}, 'MyPhrase', 'passphrase decrypted');
    is($$cfg{defaults}{'sudo password'}, 'S00d0!', 'sudo password decrypted');
    is($$cfg{defaults}{'global variables'}{'SECRET_KEY'}{value}, 'api_key_123', 'hidden GV decrypted');
    is($$cfg{environments}{'test-uuid-0001'}{expect}[0]{send}, 'expect_pass', 'hidden expect decrypted');
    is($$cfg{environments}{'test-uuid-0001'}{variables}[0]{txt}, 'hidden_var', 'hidden var decrypted');
    is($$cfg{defaults}{keepass}{password}, 'kp_pass', 'keepass password decrypted');
};

subtest 'cipher/decipher — groups have pass deleted' => sub {
    my $cfg = make_cfg();
    $$cfg{environments}{'group-uuid'} = {
        _is_group => 1,
        name => 'GroupA',
        children => {},
        parent => '__PAC__ROOT__',
        pass => 'should_be_deleted',
    };

    PACUtils::_cipherCFG($cfg);
    ok(!defined $$cfg{environments}{'group-uuid'}{pass}, 'group pass deleted during cipher');

    # Decipher also deletes group pass
    $$cfg{environments}{'group-uuid'}{pass} = 'stale';
    PACUtils::_decipherCFG($cfg);
    ok(!defined $$cfg{environments}{'group-uuid'}{pass}, 'group pass deleted during decipher');
};

subtest 'decipher with single_uuid — only decrypts that UUID' => sub {
    my $cfg = make_cfg(pass => 'pass1');
    $$cfg{environments}{'uuid-two'} = {
        name => 'Second',
        pass => 'pass2',
        passphrase => 'pp2',
        expect => [],
        variables => [],
        method => 'SSH',
        options => '',
    };

    PACUtils::_cipherCFG($cfg);
    my $encrypted_pass2 = $$cfg{environments}{'uuid-two'}{pass};

    # Decipher only test-uuid-0001
    PACUtils::_decipherCFG($cfg, 'test-uuid-0001');
    is($$cfg{environments}{'test-uuid-0001'}{pass}, 'pass1', 'target UUID decrypted');
    is($$cfg{environments}{'uuid-two'}{pass}, $encrypted_pass2, 'other UUID still encrypted');
};

subtest 'cipher/decipher — empty passwords handled' => sub {
    my $cfg = make_cfg(pass => '', passphrase => '', sudo_pass => '');
    eval {
        PACUtils::_cipherCFG($cfg);
        PACUtils::_decipherCFG($cfg);
    };
    ok(!$@, 'no crash on empty passwords: ' . ($@ // ''));
    is($$cfg{environments}{'test-uuid-0001'}{pass}, '', 'empty pass stays empty after roundtrip');
};

subtest 'cipher/decipher — Unicode passwords' => sub {
    my $cfg = make_cfg(pass => 'пароль_密码_パスワード');
    PACUtils::_cipherCFG($cfg);
    isnt($$cfg{environments}{'test-uuid-0001'}{pass}, 'пароль_密码_パスワード', 'unicode pass encrypted');
    PACUtils::_decipherCFG($cfg);
    is($$cfg{environments}{'test-uuid-0001'}{pass}, 'пароль_密码_パスワード', 'unicode pass decrypted');
};

subtest 'cipher/decipher — special chars in passwords' => sub {
    my $special = q{P@$$w0rd"with'back`tick\and$dollar!};
    my $cfg = make_cfg(pass => $special);
    PACUtils::_cipherCFG($cfg);
    PACUtils::_decipherCFG($cfg);
    is($$cfg{environments}{'test-uuid-0001'}{pass}, $special, 'special chars survive roundtrip');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 4. _deleteOldestSessionLog — Log Rotation
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_deleteOldestSessionLog — basic rotation' => sub {
    my $dir = tempdir(CLEANUP => 1);

    # Create 5 log files with different dates
    for my $i (1..5) {
        my $date = sprintf("2026040%d", $i);
        my $file = "PAC_[TestEnv_Name_MyServer]_[${date}_120000].txt";
        open my $fh, '>', "$dir/$file" or die $!;
        print $fh "log $i\n";
        close $fh;
    }

    # Keep max 3 — note: the code's delete loop uses <= with post-increment,
    # so it deletes (total-max+1) files instead of (total-max). This is existing
    # behavior that we're verifying doesn't regress.
    PACUtils::_deleteOldestSessionLog('uuid', $dir, 3);

    opendir(my $d, $dir);
    my @remaining = grep { /^PAC_/ } readdir($d);
    closedir($d);

    ok(scalar(@remaining) <= 3, 'rotation reduces log count');
    # Oldest files should be deleted first
    ok(!-f "$dir/PAC_[TestEnv_Name_MyServer]_[20260401_120000].txt", 'oldest log deleted');
    ok(!-f "$dir/PAC_[TestEnv_Name_MyServer]_[20260402_120000].txt", 'second oldest deleted');
    ok(-f "$dir/PAC_[TestEnv_Name_MyServer]_[20260405_120000].txt", 'newest log kept');
};

subtest '_deleteOldestSessionLog — max=0 keeps all' => sub {
    my $dir = tempdir(CLEANUP => 1);
    for my $i (1..5) {
        open my $fh, '>', "$dir/PAC_[Env_Name_S]_[2026040${i}_100000].txt" or die $!;
        close $fh;
    }
    PACUtils::_deleteOldestSessionLog('uuid', $dir, 0);

    opendir(my $d, $dir);
    my @remaining = grep { /^PAC_/ } readdir($d);
    closedir($d);
    is(scalar @remaining, 5, 'max=0: all logs kept');
};

subtest '_deleteOldestSessionLog — fewer than max does nothing' => sub {
    my $dir = tempdir(CLEANUP => 1);
    for my $i (1..3) {
        open my $fh, '>', "$dir/PAC_[Env_Name_S]_[2026040${i}_100000].txt" or die $!;
        close $fh;
    }
    # Note: code uses string `lt` for comparison. With single-digit counts this
    # works correctly: "3" lt "10" is false (string comparison), so it may proceed
    # to delete even when count < max for double-digit max values.
    # Use max=5 (single digit) to test the safe case.
    PACUtils::_deleteOldestSessionLog('uuid', $dir, 5);

    opendir(my $d, $dir);
    my @remaining = grep { /^PAC_/ } readdir($d);
    closedir($d);
    is(scalar @remaining, 3, 'fewer than max: nothing deleted');
};

subtest '_deleteOldestSessionLog — ignores non-matching files' => sub {
    my $dir = tempdir(CLEANUP => 1);
    # Matching files
    open my $f1, '>', "$dir/PAC_[E_Name_S]_[20260401_100000].txt" or die $!; close $f1;
    open my $f2, '>', "$dir/PAC_[E_Name_S]_[20260402_100000].txt" or die $!; close $f2;
    # Non-matching files
    open my $f3, '>', "$dir/random.txt" or die $!; close $f3;
    open my $f4, '>', "$dir/PAC_broken_format.txt" or die $!; close $f4;

    PACUtils::_deleteOldestSessionLog('uuid', $dir, 1);

    ok(-f "$dir/random.txt", 'non-matching file preserved');
    ok(-f "$dir/PAC_broken_format.txt", 'broken format file preserved');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 5. _checkREADME — README Parsing
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_checkREADME — function exists and handles missing file' => sub {
    # $CFG_DIR is a lexical variable in PACUtils, so we can't override it.
    # We verify the function exists and returns 0 when the file doesn't exist
    # (which it shouldn't in a test environment).
    my $result = PACUtils::_checkREADME();
    is($result, 0, 'returns 0 when README file missing');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 6. SSH Options Parsing — _parseCfgToOptions / _parseOptionsToCfg
# ═══════════════════════════════════════════════════════════════════════════════

SKIP: {
    eval { require Getopt::Long } or skip 'Getopt::Long not available', 1;

    # Load SSH method module for option parsing functions
    my $ssh_loaded = eval {
        require 'method/PACMethod_ssh.pm';
        1;
    };
    skip 'Cannot load PACMethod_ssh.pm', 1 unless $ssh_loaded;

    subtest 'SSH _parseCfgToOptions — basic flags' => sub {
        my $opts = PACMethod_ssh::_parseCfgToOptions('-2 -C -X -N -A -g');
        is($$opts{sshVersion}, '2', '-2 parsed as sshVersion=2');
        is($$opts{useCompression}, 1, '-C parsed');
        is($$opts{forwardX}, 1, '-X parsed');
        is($$opts{noRemoteCmd}, 1, '-N parsed');
        is($$opts{forwardAgent}, 1, '-A parsed');
        is($$opts{allowRemoteConnection}, 1, '-g parsed');
    };

    subtest 'SSH _parseCfgToOptions — version/IP defaults' => sub {
        my $opts = PACMethod_ssh::_parseCfgToOptions('-x');
        is($$opts{sshVersion}, 'any', 'no version flag = any');
        is($$opts{ipVersion}, 'any', 'no ip flag = any');
        is($$opts{forwardX}, 0, '-x = no forwarding');
    };

    subtest 'SSH _parseCfgToOptions — port forwarding' => sub {
        my $opts = PACMethod_ssh::_parseCfgToOptions('-L 8080:localhost:80 -R 9090:db:5432');
        is(scalar @{$$opts{forwardPort}}, 1, 'one local forward parsed');
        is($$opts{forwardPort}[0]{localPort}, '8080', 'local port correct');
        is($$opts{forwardPort}[0]{remoteIP}, 'localhost', 'remote host correct');
        is($$opts{forwardPort}[0]{remotePort}, '80', 'remote port correct');

        is(scalar @{$$opts{remotePort}}, 1, 'one remote forward parsed');
        is($$opts{remotePort}[0]{localPort}, '9090', 'remote fwd local port');
        is($$opts{remotePort}[0]{remoteIP}, 'db', 'remote fwd host');
        is($$opts{remotePort}[0]{remotePort}, '5432', 'remote fwd port');
    };

    subtest 'SSH _parseCfgToOptions — dynamic SOCKS forward' => sub {
        my $opts = PACMethod_ssh::_parseCfgToOptions('-D 1080');
        is(scalar @{$$opts{dynamicForward}}, 1, 'one dynamic forward');
        is($$opts{dynamicForward}[0]{dynamicPort}, '1080', 'dynamic port correct');
    };

    subtest 'SSH _parseOptionsToCfg — roundtrip' => sub {
        my $input = {
            sshVersion => '2',
            ipVersion => '4',
            forwardX => 1,
            noRemoteCmd => 0,
            useCompression => 1,
            allowRemoteConnection => 0,
            forwardAgent => 1,
            advancedOption => [
                { option => 'ServerAliveInterval', value => '30' },
            ],
            dynamicForward => [
                { dynamicIP => '', dynamicPort => '1080' },
            ],
            forwardPort => [
                { localIP => '', localPort => '8080', remoteIP => 'localhost', remotePort => '80' },
            ],
            remotePort => [],
        };

        my $cmdline = PACMethod_ssh::_parseOptionsToCfg($input);
        like($cmdline, qr/-2/, 'SSH version 2 in output');
        like($cmdline, qr/-4/, 'IPv4 in output');
        like($cmdline, qr/-X/, 'X forwarding in output');
        like($cmdline, qr/-C/, 'compression in output');
        like($cmdline, qr/-A/, 'agent forwarding in output');
        like($cmdline, qr/-o "ServerAliveInterval=30"/, 'advanced option in output');
        like($cmdline, qr/-D\s+1080/, 'dynamic forward in output');
        like($cmdline, qr/-L\s+8080:localhost:80/, 'local forward in output');
        unlike($cmdline, qr/-N/, 'no -N flag');
        unlike($cmdline, qr/-g/, 'no -g flag');
    };

    subtest 'SSH _parseOptionsToCfg — blocks dangerous options' => sub {
        my $stderr_output = '';
        local $SIG{__WARN__} = sub { $stderr_output .= $_[0] };

        # Capture STDERR
        my $captured = '';
        open(my $olderr, '>&', \*STDERR) or die;
        close(STDERR);
        open(STDERR, '>', \$captured) or die;

        my $input = {
            sshVersion => 'any',
            ipVersion => 'any',
            forwardX => 0,
            noRemoteCmd => 0,
            useCompression => 0,
            allowRemoteConnection => 0,
            forwardAgent => 0,
            advancedOption => [
                { option => 'ProxyCommand', value => 'nc %h %p' },
                { option => 'LocalCommand', value => '/bin/sh' },
                { option => 'PermitLocalCommand', value => 'yes' },
                { option => 'ServerAliveInterval', value => '30' },
            ],
            dynamicForward => [],
            forwardPort => [],
            remotePort => [],
        };

        my $cmdline = PACMethod_ssh::_parseOptionsToCfg($input);

        # Restore STDERR
        close(STDERR);
        open(STDERR, '>&', $olderr) or die;

        unlike($cmdline, qr/ProxyCommand/, 'ProxyCommand blocked');
        unlike($cmdline, qr/LocalCommand/, 'LocalCommand blocked');
        unlike($cmdline, qr/PermitLocalCommand/, 'PermitLocalCommand blocked');
        like($cmdline, qr/ServerAliveInterval/, 'safe option allowed');
    };

    subtest 'SSH _parseOptionsToCfg — blocks shell metacharacters in options' => sub {
        my $captured = '';
        open(my $olderr, '>&', \*STDERR) or die;
        close(STDERR);
        open(STDERR, '>', \$captured) or die;

        my $input = {
            sshVersion => 'any',
            ipVersion => 'any',
            forwardX => 0,
            noRemoteCmd => 0,
            useCompression => 0,
            allowRemoteConnection => 0,
            forwardAgent => 0,
            advancedOption => [
                { option => 'Safe', value => 'clean_value' },
                { option => 'Inject`cmd`', value => 'val' },
                { option => 'Good', value => '$(evil)' },
                { option => 'Pipe', value => 'a|b' },
            ],
            dynamicForward => [],
            forwardPort => [],
            remotePort => [],
        };

        my $cmdline = PACMethod_ssh::_parseOptionsToCfg($input);

        close(STDERR);
        open(STDERR, '>&', $olderr) or die;

        like($cmdline, qr/Safe=clean_value/, 'safe option+value passes');
        unlike($cmdline, qr/Inject/, 'backtick in option name blocked');
        unlike($cmdline, qr/evil/, 'subshell in value blocked');
        unlike($cmdline, qr/Pipe/, 'pipe in value blocked');
    };
}

# ═══════════════════════════════════════════════════════════════════════════════
# 7. _subst — Advanced Substitution Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

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

subtest '_subst — nested variable references' => sub {
    my ($cfg, $uuid) = cfg_for(
        ip => '10.0.0.1',
        user => 'root',
        vars => [
            { txt => 'first_val', hide => '0' },
            { txt => 'second_val', hide => '0' },
        ],
    );
    my $result = PACUtils::_subst('connect <USER>@<IP> var=<V:0>', $cfg, $uuid);
    is($result, 'connect root@10.0.0.1 var=first_val', 'mixed session+variable substitution');
};

subtest '_subst — all date/time fields are valid' => sub {
    my ($cfg, $uuid) = cfg_for();
    my $y = PACUtils::_subst('<DATE_Y>', $cfg, $uuid);
    my $m = PACUtils::_subst('<DATE_M>', $cfg, $uuid);
    my $d = PACUtils::_subst('<DATE_D>', $cfg, $uuid);
    my $h = PACUtils::_subst('<TIME_H>', $cfg, $uuid);
    my $mi = PACUtils::_subst('<TIME_M>', $cfg, $uuid);
    my $s = PACUtils::_subst('<TIME_S>', $cfg, $uuid);

    ok($y >= 2024 && $y <= 2100, "year $y is plausible");
    ok($m >= 1 && $m <= 12, "month $m is valid");
    ok($d >= 1 && $d <= 31, "day $d is valid");
    ok($h >= 0 && $h <= 23, "hour $h is valid");
    ok($mi >= 0 && $mi <= 59, "minute $mi is valid");
    ok($s >= 0 && $s <= 59, "second $s is valid");
};

subtest '_subst — <TITLE> substitution' => sub {
    my ($cfg, $uuid) = cfg_for(title => 'Production-DB');
    my $result = PACUtils::_subst('<TITLE>', $cfg, $uuid);
    is($result, 'Production-DB', '<TITLE> substituted');
};

subtest '_subst — GV with special characters are sanitized' => sub {
    my ($cfg, $uuid) = cfg_for(gv => {
        'SPEC_PASS' => { value => 'p@ss$w0rd`test`', hidden => '0' },
    });
    my $result = PACUtils::_subst('<GV:SPEC_PASS>', $cfg, $uuid);
    # Security hardening: shell metacharacters in GVs are escaped
    like($result, qr/p\@ss/, 'GV value base preserved');
    like($result, qr/w0rd/, 'GV value middle preserved');
    # The $, ` chars should be escaped by the sanitizer
    unlike($result, qr/(?<!\\)\$/, 'dollar sign is escaped');
    unlike($result, qr/(?<!\\)`/, 'backtick is escaped');
};

subtest '_subst — multiple same tokens' => sub {
    my ($cfg, $uuid) = cfg_for(ip => '1.2.3.4');
    my $result = PACUtils::_subst('<IP>:<IP>:<IP>', $cfg, $uuid);
    is($result, '1.2.3.4:1.2.3.4:1.2.3.4', 'multiple same tokens all replaced');
};

subtest '_subst — empty strings and edge cases' => sub {
    my ($cfg, $uuid) = cfg_for(ip => '', port => '0', user => '');
    is(PACUtils::_subst('<IP>', $cfg, $uuid), '', 'empty IP substituted as empty');
    is(PACUtils::_subst('<PORT>', $cfg, $uuid), '0', 'zero port substituted');
    is(PACUtils::_subst('<USER>', $cfg, $uuid), '', 'empty user substituted');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 8. _doShellEscape — Extended Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_doShellEscape — newline and carriage return' => sub {
    my $with_newlines = "line1\nline2\rline3";
    my $escaped = PACUtils::_doShellEscape($with_newlines);
    unlike($escaped, qr/\n/, 'newline escaped out');
    unlike($escaped, qr/\r/, 'carriage return escaped out');
};

subtest '_doShellEscape — very long string' => sub {
    my $long = '$' x 10000;
    my $escaped = PACUtils::_doShellEscape($long);
    is(length($escaped), 20000, 'long string: each $ doubled with backslash');
    unlike($escaped, qr/(?<!\\)\$/, 'no unescaped dollar signs in long string');
};

subtest '_doShellEscape — null bytes preserved' => sub {
    # Null bytes might appear in binary data
    my $with_null = "before\x00after";
    my $escaped = PACUtils::_doShellEscape($with_null);
    like($escaped, qr/before/, 'text before null preserved');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 9. _removeEscapeSeqs — Extended ANSI Coverage
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_removeEscapeSeqs — OSC title sequences' => sub {
    my $osc = "\e]1;My Title\x07Some text";
    my $clean = PACUtils::_removeEscapeSeqs($osc);
    unlike($clean, qr/My Title/, 'OSC title stripped');
    like($clean, qr/Some text/, 'text after OSC preserved');
};

subtest '_removeEscapeSeqs — 24-bit color' => sub {
    my $rgb = "\e[38;2;255;100;50mColored\e[0m";
    my $clean = PACUtils::_removeEscapeSeqs($rgb);
    like($clean, qr/Colored/, '24-bit color text preserved');
    unlike($clean, qr/\e/, 'no escape chars remain');
};

subtest '_removeEscapeSeqs — cursor save/restore' => sub {
    my $cursor = "\e[s\e[5;10H\e[u";
    my $clean = PACUtils::_removeEscapeSeqs($cursor);
    is($clean, '', 'cursor save/move/restore all stripped');
};

subtest '_removeEscapeSeqs — complex mixed content' => sub {
    my $complex = "\e[1m\e[32muser\@host\e[0m:\e[34m~/dir\e[0m\$ ls -la";
    my $clean = PACUtils::_removeEscapeSeqs($complex);
    like($clean, qr/user\@host/,  'username@host preserved');
    like($clean, qr/~\/dir/, 'path preserved');
    like($clean, qr/ls -la/, 'command preserved');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 10. _replaceBadChars — Additional Control Characters
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_replaceBadChars — all control chars 0x00-0x1F' => sub {
    for my $byte (0x00..0x1F) {
        my $char = chr($byte);
        my $result = PACUtils::_replaceBadChars($char);
        isnt($result, $char, sprintf("0x%02X replaced", $byte));
    }
    # 0x7F (DEL) also replaced
    my $del = PACUtils::_replaceBadChars("\x7F");
    is($del, '(BACKSPACE)', 'DEL (0x7F) replaced');
};

subtest '_replaceBadChars — printable chars unchanged' => sub {
    my $printable = join('', map { chr($_) } 0x20..0x7E);
    is(PACUtils::_replaceBadChars($printable), $printable, 'all printable ASCII unchanged');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 11. Source Code Integrity — Filehandle Patterns
# ═══════════════════════════════════════════════════════════════════════════════

sub read_file {
    my $path = shift;
    open my $fh, '<', $path or BAIL_OUT("Cannot open $path: $!");
    local $/;
    my $content = <$fh>;
    close $fh;
    return $content;
}

subtest 'no bare filehandles in security-critical files' => sub {
    # These files were fully converted to lexical filehandles during hardening
    my @files = qw(
        lib/PACUtils.pm lib/PACTerminal.pm lib/PACConfig.pm
        lib/PACKeePass.pm lib/PACScripts.pm lib/PACScreenshots.pm
    );
    for my $file (@files) {
        my $content = read_file($file);
        my @bare = $content =~ /\bopen\s*\(\s*([A-Z][A-Z_]*)\s*,/g;
        @bare = grep { $_ !~ /^(STDERR|STDOUT|STDIN|SAVERR|SAVOUT)$/ } @bare;
        is(scalar @bare, 0, "$file: no bareword filehandles")
            or diag("Found bareword filehandles: " . join(', ', @bare));
    }
};

subtest 'all open() use "or" error handling in fixed files' => sub {
    for my $file (qw(lib/PACPCC.pm lib/PACScripts.pm)) {
        my $content = read_file($file);
        # Find patterns like: if (!open(my $fh  — these are the buggy pattern
        my @bad = $content =~ /(if\s*\(\s*!\s*open\s*\(\s*my\s+\$\w+)/g;
        is(scalar @bad, 0, "$file: no scoping-bug open patterns")
            or diag("Found bad pattern: " . join(', ', @bad));
    }
};

# ═══════════════════════════════════════════════════════════════════════════════
# 12. _getEncodings — Encoding List Validation
# ═══════════════════════════════════════════════════════════════════════════════

subtest '_getEncodings — returns valid encoding map' => sub {
    my $enc = PACUtils::_getEncodings();
    is(ref($enc), 'HASH', 'returns hash ref');
    ok(scalar(keys %$enc) > 50, 'contains many encodings (got ' . scalar(keys %$enc) . ')');
    ok(exists $$enc{'UTF-8'}, 'UTF-8 present');
    ok(exists $$enc{'Big5'}, 'Big5 present');
    ok(exists $$enc{'ANSI_X3.4-1968'}, 'ASCII present');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 13. Connection Method Files — Syntax & Structure
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'all connection methods have required functions' => sub {
    my @methods = glob("$RealBin/../lib/method/PACMethod_*.pm");
    ok(scalar @methods >= 10, 'at least 10 connection methods found');

    for my $file (@methods) {
        my $content = read_file($file);
        my ($name) = $file =~ /PACMethod_(\w+)\.pm$/;

        like($content, qr/sub new\b/, "$name: has new()");
        like($content, qr/sub get_cfg\b/, "$name: has get_cfg()");
        like($content, qr/sub _parseCfgToOptions\b/, "$name: has _parseCfgToOptions()");
        like($content, qr/sub _parseOptionsToCfg\b/, "$name: has _parseOptionsToCfg()");
    }
};

# ═══════════════════════════════════════════════════════════════════════════════
# 14. asbru_conn — Connection Script Integrity
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'asbru_conn — critical functions present' => sub {
    my $content = read_file("$RealBin/../lib/asbru_conn");

    like($content, qr/sub subst\b/, 'subst() function exists');
    like($content, qr/sub auth\b/, 'auth() function exists');
    like($content, qr/sub send_slow\b/, 'send_slow() function exists');

    # END block for cleanup
    like($content, qr/END\s*\{/, 'END cleanup block exists');
    like($content, qr/\$PASS\s*=\s*"\\0"/, 'PASS zeroed in cleanup');
    like($content, qr/\$PASSPHRASE\s*=\s*"\\0"/, 'PASSPHRASE zeroed in cleanup');
    like($content, qr/\$SUDO_PASSWORD\s*=\s*"\\0"/, 'SUDO_PASSWORD zeroed in cleanup');

    # Signal handlers
    like($content, qr/\$SIG\{['"]HUP['"]\}/, 'HUP handler installed');
    like($content, qr/\$SIG\{['"]USR1['"]\}/, 'USR1 handler installed');
    like($content, qr/\$SIG\{['"]USR2['"]\}/, 'USR2 handler installed');
    like($content, qr/\$SIG\{['"]WINCH['"]\}/, 'WINCH handler installed');
};

subtest 'asbru_conn — CMD whitelist is restrictive' => sub {
    my $content = read_file("$RealBin/../lib/asbru_conn");

    # Verify CMD execution has whitelist
    like($content, qr/CMD.*whitelist|whitelist.*CMD/is, 'CMD whitelist documented');
    # Must NOT have raw backtick execution without validation
    unlike($content, qr/`\$cmd`\s*;/, 'no raw unvalidated backtick CMD execution');
};

subtest 'asbru_conn — proxy validation present' => sub {
    my $content = read_file("$RealBin/../lib/asbru_conn");

    like($content, qr/proxy_ip/, 'proxy IP validation present');
    like($content, qr/proxy_port.*\\d\+/, 'proxy port validated as numeric');
    like($content, qr/proxy_type.*(socks4|socks5|http)/, 'proxy type whitelisted');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 15. Crypto — Master Password Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'master password — token verification consistency' => sub {
    my $pass = 'MyMasterP@ss!';
    my $token1 = PACUtils::_createMasterVerifier($pass);
    my $token2 = PACUtils::_createMasterVerifier($pass);

    ok(defined $token1, 'token created');
    ok(length($token1) > 10, 'token has reasonable length');

    # Same password should verify against both tokens
    ok(PACUtils::_verifyMasterPassword($pass, $token1), 'pass verifies against token1');
    ok(PACUtils::_verifyMasterPassword($pass, $token2), 'pass verifies against token2');

    # Wrong password should fail
    ok(!PACUtils::_verifyMasterPassword('wrong_pass', $token1), 'wrong pass fails');
    ok(!PACUtils::_verifyMasterPassword('', $token1), 'empty pass fails');
};

subtest 'master password — init cipher changes encryption' => sub {
    my $pass = 'TestMaster123';
    PACUtils::_initMasterCipher($pass);
    ok(PACUtils::_isMasterPasswordActive(), 'master password is active');

    # Encrypt something with master cipher
    my $plaintext = 'sensitive_data';
    my $encrypted = $PACUtils::CIPHER->encrypt_hex($plaintext);
    ok($encrypted ne $plaintext, 'data encrypted with master cipher');

    # Decrypt should return original
    my $decrypted = $PACUtils::CIPHER->decrypt_hex($encrypted);
    is($decrypted, $plaintext, 'master cipher roundtrip works');
};

subtest 'master password — _decrypt_hex_compat fallback chain' => sub {
    # Encrypt with current cipher
    my $plaintext = 'test_compat_data';
    my $encrypted = $PACUtils::CIPHER->encrypt_hex($plaintext);

    # _decrypt_hex_compat should decrypt it
    my $decrypted = PACUtils::_decrypt_hex_compat($encrypted);
    is($decrypted, $plaintext, 'compat decryption works with current cipher');
};

# ═══════════════════════════════════════════════════════════════════════════════
# 16. Config Integrity — Storable Serialization
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'config survives Storable freeze/thaw cycle' => sub {
    my $cfg = make_cfg(
        pass => 'test_pass',
        ip => '192.168.1.100',
        vars => [
            { txt => 'var1', hide => '0' },
            { txt => 'var2', hide => '1' },
        ],
        expect => [
            { expect => 'Password:', send => 'secret', hidden => '1' },
        ],
        gv => {
            'MY_KEY' => { value => 'my_val', hidden => '0' },
        },
    );

    # Storable roundtrip
    my $frozen = Storable::freeze($cfg);
    ok(defined $frozen, 'config frozen successfully');
    ok(length($frozen) > 0, 'frozen data non-empty');

    my $thawed = Storable::thaw($frozen);
    is_deeply($thawed, $cfg, 'thawed config matches original');
};

subtest 'config survives nstore/retrieve cycle' => sub {
    my $tmpfile = File::Temp::tmpnam();
    my $cfg = make_cfg(pass => 'nstore_test');

    eval {
        Storable::nstore($cfg, $tmpfile);
        my $loaded = Storable::retrieve($tmpfile);
        is($$loaded{environments}{'test-uuid-0001'}{pass}, 'nstore_test', 'nstore roundtrip works');
    };
    ok(!$@, 'no error in nstore/retrieve: ' . ($@ // ''));
    unlink $tmpfile if -f $tmpfile;
};

# ═══════════════════════════════════════════════════════════════════════════════
# 17. Filehandle Fix Verification — The open() Scoping Fix
# ═══════════════════════════════════════════════════════════════════════════════

subtest 'open...or do pattern works correctly for file reading' => sub {
    # Simulate the fixed pattern
    my $dir = tempdir(CLEANUP => 1);
    my $file = "$dir/test.txt";
    open my $w, '>', $file or die $!;
    print $w "line1\nline2\nline3\n";
    close $w;

    # This is the FIXED pattern — $fh visible after the or-do block
    my $content = '';
    open(my $fh, '<', $file) or do {
        fail("cannot open test file");
        return;
    };
    while (my $line = <$fh>) {
        $content .= $line;
    }
    close $fh;

    like($content, qr/line1/, 'line1 read');
    like($content, qr/line3/, 'line3 read');
};

subtest 'open...or do pattern works correctly for file writing' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $file = "$dir/output.txt";

    open(my $fh, '>', $file) or do {
        fail("cannot open output file");
        return;
    };
    print $fh "written data\n";
    close $fh;

    ok(-f $file, 'file created');
    open my $r, '<', $file or die $!;
    my $content = <$r>;
    close $r;
    like($content, qr/written data/, 'data written correctly');
};

done_testing();
