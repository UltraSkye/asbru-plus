#!/usr/bin/perl
# t/07-utils-extended.t — Extended unit tests for pure functions in PACUtils.pm
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

# ── _doShellEscape — complete character coverage ──────────────────────────────

subtest '_doShellEscape — shell-sensitive chars' => sub {
    # Characters that must be escaped
    is(PACUtils::_doShellEscape('pa$$word'),      'pa\$\$word',         'two dollar signs');
    is(PACUtils::_doShellEscape('`cmd`'),          '\`cmd\`',            'backticks');
    is(PACUtils::_doShellEscape('"quote"'),        '\"quote\"',          'double quotes');
    is(PACUtils::_doShellEscape('back\\slash'),    'back\\\\slash',      'backslash doubled');
    is(PACUtils::_doShellEscape('$`"\\'),          '\$\`\"\\\\',         'all four specials combined');

    # Characters that must NOT be escaped (safe for double-quote context)
    is(PACUtils::_doShellEscape("single'quote"),   "single'quote",       'single quote not escaped');
    is(PACUtils::_doShellEscape('semi;colon'),     'semi;colon',         'semicolon not escaped');
    is(PACUtils::_doShellEscape('pipe|char'),      'pipe|char',          'pipe not escaped');
    is(PACUtils::_doShellEscape('amp&ersand'),     'amp&ersand',         'ampersand not escaped');
    is(PACUtils::_doShellEscape('paren(test)'),    'paren(test)',         'parens not escaped');
    is(PACUtils::_doShellEscape('has spaces'),     'has spaces',         'spaces not escaped');
    is(PACUtils::_doShellEscape(''),               '',                   'empty string');

    # Unicode / UTF-8 should pass through
    is(PACUtils::_doShellEscape('пароль'),         'пароль',             'cyrillic unchanged');
    is(PACUtils::_doShellEscape('パスワード'),      'パスワード',          'japanese unchanged');
};

# ── _removeEscapeSeqs — comprehensive ANSI coverage ──────────────────────────

subtest '_removeEscapeSeqs — ANSI escape sequences' => sub {
    is(PACUtils::_removeEscapeSeqs('plain'),                 'plain',       'plain text unchanged');
    is(PACUtils::_removeEscapeSeqs(''),                      '',            'empty string');

    # SGR (colour / attribute) sequences
    is(PACUtils::_removeEscapeSeqs("\e[0m"),                 '',            'reset SGR');
    is(PACUtils::_removeEscapeSeqs("\e[1mBold\e[0m"),        'Bold',        'bold on/off');
    is(PACUtils::_removeEscapeSeqs("\e[1;32mGreen\e[0m"),    'Green',       'compound SGR');
    is(PACUtils::_removeEscapeSeqs("\e[38;5;196mRed\e[0m"),  'Red',         '256-colour SGR');

    # Cursor movement sequences
    is(PACUtils::_removeEscapeSeqs("\e[2J"),                 '',            'clear screen (ED)');
    is(PACUtils::_removeEscapeSeqs("\e[H"),                  '',            'cursor home');
    is(PACUtils::_removeEscapeSeqs("\e[3;5H"),               '',            'cursor position');
    is(PACUtils::_removeEscapeSeqs("\e[1A"),                 '',            'cursor up');

    # Mode-switch sequences
    is(PACUtils::_removeEscapeSeqs("\e="),                   '',            'alternate keypad');
    is(PACUtils::_removeEscapeSeqs("\e>"),                   '',            'normal keypad');

    # Mixed content: escape seqs stripped, text preserved
    my $mixed = "\e[1mUser\e[0m: \e[32mroot\e[0m";
    is(PACUtils::_removeEscapeSeqs($mixed),                  'User: root',  'text survives stripping');

    # Consecutive sequences
    is(PACUtils::_removeEscapeSeqs("\e[1m\e[2m\e[0m"),       '',            'consecutive SGR all removed');
};

# ── _replaceBadChars — control character mapping ──────────────────────────────

subtest '_replaceBadChars — control characters' => sub {
    is(PACUtils::_replaceBadChars(''),             '',                         'empty string');
    is(PACUtils::_replaceBadChars('normal'),       'normal',                   'normal text unchanged');

    # Replacements are wrapped in single quotes by the source (e.g. 'NUL (null)')
    is(PACUtils::_replaceBadChars("\x00"),         "'NUL (null)'",             'NUL → text');
    is(PACUtils::_replaceBadChars("\x07"),         "'BEL (bell)'",             'BEL → text');
    is(PACUtils::_replaceBadChars("\x08"),         "'BS (backspace)'",         'BS → text');
    is(PACUtils::_replaceBadChars("\x0A"),         "'LF (NL New Line)'",       'LF → text');
    is(PACUtils::_replaceBadChars("\x0D"),         "'CR (carriage return)'",   'CR → text');
    is(PACUtils::_replaceBadChars("\x1B"),         "'ESC (escape)'",           'ESC → text');
    # DEL uses different format (no quotes)
    is(PACUtils::_replaceBadChars("\x7f"),         '(BACKSPACE)',              'DEL → (BACKSPACE)');

    is(PACUtils::_replaceBadChars("abc\n"),        "abc'LF (NL New Line)'",    'LF in real string');

    # Multiple control chars in one string
    my $s = PACUtils::_replaceBadChars("\x00\x1B");
    like($s, qr/NUL/,   'multiple: NUL present');
    like($s, qr/ESC/,   'multiple: ESC present');
};

# ── _appName — format check ───────────────────────────────────────────────────

subtest '_appName' => sub {
    my $name = PACUtils::_appName();
    ok(defined $name,          '_appName returns a value');
    like($name, qr/\S/,        '_appName non-empty');
    like($name, qr/\d+\.\d+/,  '_appName contains version number');
};

done_testing();
