#!/usr/bin/perl
# t/01-utils-functions.t — Unit tests for pure functions in PACUtils.pm
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

# Load mocks before the real module
use lib "$RealBin/lib";
use lib "$RealBin/../lib";

# We need to stub out heavy dependencies before loading PACUtils
BEGIN {
    # Stub modules that require display or system libs
    $INC{'Gtk3.pm'}     = 1;
    $INC{'Glib.pm'}     = 1;
    $INC{'Pango.pm'}    = 1;
    $INC{'Cairo.pm'}    = 1;

    # Provide minimal stubs
    package Gtk3;
    sub import {}
    sub init   {}

    package Glib;
    sub import {}

    package Glib::Object::Introspection;
    sub setup {}

    package Cairo;
    sub import {}

    package main;
}

# Load only the specific functions we want to test
# by requiring the module after stubs are in place
require PACUtils;
PACUtils->import(qw(_doShellEscape _removeEscapeSeqs));

# ── _doShellEscape ────────────────────────────────────────────────────────────

subtest '_doShellEscape' => sub {
    is(PACUtils::_doShellEscape('hello'),          'hello',            'plain string unchanged');
    is(PACUtils::_doShellEscape('pass$word'),      'pass\$word',       'dollar sign escaped');
    is(PACUtils::_doShellEscape('back`tick'),      'back\`tick',       'backtick escaped');
    is(PACUtils::_doShellEscape('double"quote'),   'double\"quote',    'double quote escaped');
    is(PACUtils::_doShellEscape('back\\slash'),    'back\\\\slash',    'backslash escaped');
    is(PACUtils::_doShellEscape(''),               '',                 'empty string');
    is(PACUtils::_doShellEscape('p@ss!w0rd'),      'p@ss!w0rd',        'safe special chars unchanged');
    is(PACUtils::_doShellEscape('has spaces'),     'has spaces',       'spaces unchanged');

    # Combination — password with multiple special chars
    is(PACUtils::_doShellEscape('$ec`ret"\\key'),  '\$ec\`ret\"\\\\key', 'all special chars');
};

# ── _removeEscapeSeqs ─────────────────────────────────────────────────────────

subtest '_removeEscapeSeqs' => sub {
    is(PACUtils::_removeEscapeSeqs('plain text'),       'plain text',   'plain text unchanged');
    is(PACUtils::_removeEscapeSeqs("\e[0mtext"),        'text',         'ANSI reset removed');
    is(PACUtils::_removeEscapeSeqs("\e[1;32mgreen\e[0m"), 'green',      'ANSI color removed');
    is(PACUtils::_removeEscapeSeqs("\e[2Jclear"),       'clear',        'ANSI clear removed');
    is(PACUtils::_removeEscapeSeqs(''),                 '',             'empty string');
    is(PACUtils::_removeEscapeSeqs("\e=normal"),        'normal',       'ANSI mode escape removed');
    is(PACUtils::_removeEscapeSeqs("\e>normal"),        'normal',       'ANSI alternate mode removed');

    # Multi-line with escapes
    my $dirty = "\e[1mBold\e[0m and \e[32mgreen\e[0m";
    is(PACUtils::_removeEscapeSeqs($dirty), 'Bold and green', 'multiple ANSI sequences removed');
};

done_testing();
