#!/usr/bin/perl
# t/65-glade-getter.t — PACUtils::_ (the glade-object getter) must be a real,
# callable symbol.
#
# On Perl 5.38+, `sub _ { ... }` is silently NOT installed into the package
# symbol table (the name `_` is reserved). Legacy bareword `_($self, 'name')`
# call sites still bind at compile time, but a fully-qualified `PACUtils::_(...)`
# call — as used by PAC::Theme::Widget — dies with "Undefined subroutine
# &PACUtils::_". Installing the getter via typeglob (`*PACUtils::_ = sub {...}`)
# lands it in the symbol table so both call styles work.
use strict;
use warnings;
use FindBin qw($RealBin);
use Test::More;

# 1. Executable proof of the constraint this fix exists for.
subtest 'Perl drops `sub _ {}` but keeps a typeglob install' => sub {
    package T::SubForm;   sub _ { 1 }
    package T::GlobForm;  BEGIN { *T::GlobForm::_ = sub { 1 }; }
    package main;
    ok(!defined &T::SubForm::_,
        '`sub _ {}` is not installed into the symbol table on this Perl');
    ok(defined &T::GlobForm::_,
        'typeglob assignment installs a callable &_');
};

# 2. Source guard: PACUtils must install _ via typeglob, never bare `sub _ {`.
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open PACUtils.pm: $!";
    local $/; <$f>;
};
like($utils, qr/\*PACUtils::_\s*=\s*sub/,
    'PACUtils installs the glade getter via typeglob');
unlike($utils, qr/^\s*sub\s+_\s*[\{\(]/m,
    'PACUtils does not use the bare `sub _` form (silently dropped on 5.38+)');

# 3. Functional guard when the runtime deps are available (CI has Gtk3 etc.).
SKIP: {
    my $loaded = eval {
        local @INC = ("$RealBin/../lib", @INC);
        require PACUtils;
        1;
    };
    skip "PACUtils runtime deps not installed: $@", 2 unless $loaded;

    ok(defined &PACUtils::_,
        '&PACUtils::_ is defined after loading PACUtils');

    my $glade = do {
        package T::FakeGlade;
        sub get_object { return "obj:$_[1]" }
        bless {}, 'T::FakeGlade';
    };
    my $self = { _GLADE => $glade };
    is(PACUtils::_($self, 'someWidget'), 'obj:someWidget',
        'fully-qualified PACUtils::_ resolves a widget by name');
}

done_testing();
