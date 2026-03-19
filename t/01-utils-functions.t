#!/usr/bin/perl
# t/01-utils-functions.t — Unit tests for pure functions in PACUtils.pm
use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

# Add all lib paths so local shims (lib/ex/) are found first
use lib "$RealBin/../lib/ex";   # local Glib::IO shim, SortedTreeStore, etc.
use lib "$RealBin/../lib";
use lib "$RealBin/lib";         # test mocks (Gtk3, Glib, Pango stubs)

BEGIN {
    # Mark all heavy GUI modules as "already loaded" so their `use` statements
    # in PACUtils.pm are no-ops. Order matters: set %INC before any require.
    my @stub_modules = qw(
        Gtk3
        Gtk3::Gdk
        Glib
        Glib::IO
        Glib::Object::Introspection
        Pango
        Cairo
        SortedTreeStore
        Gnome2::Wnck
        Vte2ext
    );
    for my $mod (@stub_modules) {
        (my $file = $mod) =~ s|::|/|g;
        $INC{"$file.pm"} //= 1;
    }

    # Minimal package stubs so method calls don't die
    package Gtk3;
    sub import {}
    sub init              { 1 }
    # Called as barewords (no parens) in PACUtils.pm under strict subs
    sub events_pending    { 0 }
    sub main_iteration    { 0 }
    sub main_iteration_do { 0 }
    sub main_quit         {}
    sub main              {}
    sub TRUE              { 1 }
    sub FALSE             { 0 }

    package Gtk3::Gdk;
    sub import {}
    our $AUTOLOAD;
    sub AUTOLOAD { return if $AUTOLOAD =~ /::DESTROY$/; return bless {}, 'Gtk3::Gdk' }
    sub DESTROY  {}

    package Gtk3::Gdk::Pixbuf;
    sub import {}
    sub new                    { bless {}, 'Gtk3::Gdk::Pixbuf' }
    sub new_from_file          { bless {}, 'Gtk3::Gdk::Pixbuf' }
    sub new_from_file_at_scale { bless {}, 'Gtk3::Gdk::Pixbuf' }
    our $AUTOLOAD;
    sub AUTOLOAD { return if $AUTOLOAD =~ /::DESTROY$/; return bless {}, 'Gtk3::Gdk::Pixbuf' }
    sub DESTROY  {}

    package Glib;
    sub import {}

    package Glib::IO;
    sub import {}
    sub add_watch { 0 }

    package Glib::Object::Introspection;
    sub setup  { 1 }
    sub import {}

    package Pango;
    sub import {}

    package Cairo;
    sub import {}

    package SortedTreeStore;
    sub new    { bless {}, shift }
    sub import {}

    package main;
}

# Suppress Socket6 "subroutine redefined" warnings that are harmless
local $SIG{__WARN__} = sub {
    warn @_ unless $_[0] =~ /redefined/i;
};

eval { require PACUtils } or BAIL_OUT("Cannot load PACUtils: $@");

# ── _doShellEscape ────────────────────────────────────────────────────────────

subtest '_doShellEscape' => sub {
    is(PACUtils::_doShellEscape('hello'),          'hello',              'plain string unchanged');
    is(PACUtils::_doShellEscape('pass$word'),      'pass\$word',         'dollar sign escaped');
    is(PACUtils::_doShellEscape('back`tick'),      'back\`tick',         'backtick escaped');
    is(PACUtils::_doShellEscape('double"quote'),   'double\"quote',      'double quote escaped');
    is(PACUtils::_doShellEscape('back\\slash'),    'back\\\\slash',      'backslash escaped');
    is(PACUtils::_doShellEscape(''),               '',                   'empty string');
    is(PACUtils::_doShellEscape('p@ss!w0rd'),      'p@ss!w0rd',          'safe special chars unchanged');
    is(PACUtils::_doShellEscape('has spaces'),     'has spaces',         'spaces unchanged');
    is(PACUtils::_doShellEscape('$ec`ret"\\key'),  '\$ec\`ret\"\\\\key', 'all special chars combined');
};

# ── _removeEscapeSeqs ─────────────────────────────────────────────────────────

subtest '_removeEscapeSeqs' => sub {
    is(PACUtils::_removeEscapeSeqs('plain text'),             'plain text',    'plain text unchanged');
    is(PACUtils::_removeEscapeSeqs("\e[0mtext"),              'text',          'ANSI reset removed');
    is(PACUtils::_removeEscapeSeqs("\e[1;32mgreen\e[0m"),     'green',         'ANSI color codes removed');
    is(PACUtils::_removeEscapeSeqs("\e[2Jclear"),             'clear',         'ANSI clear sequence removed');
    is(PACUtils::_removeEscapeSeqs(''),                       '',              'empty string');
    is(PACUtils::_removeEscapeSeqs("\e=normal"),              'normal',        'ANSI mode escape removed');
    is(PACUtils::_removeEscapeSeqs("\e>normal"),              'normal',        'ANSI alternate mode removed');
    my $dirty = "\e[1mBold\e[0m and \e[32mgreen\e[0m";
    is(PACUtils::_removeEscapeSeqs($dirty), 'Bold and green', 'multiple ANSI sequences removed');
};

done_testing();
