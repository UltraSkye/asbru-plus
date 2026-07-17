#!/usr/bin/perl
# t/65-glade-getter.t - PACUtils::_ (the glade-object getter) must be a real,
# callable symbol.
#
# On Perl 5.38+, `sub _ { ... }` is silently NOT installed into the package
# symbol table (the name `_` is reserved). Legacy bareword `_($self, 'name')`
# call sites still bind at compile time, but a fully-qualified `PACUtils::_(...)`
# call - as used by PAC::Theme::Widget - dies with "Undefined subroutine
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

# 3. Functional guard: eval PACUtils' actual install statement (Gtk-free) and
#    assert the resulting &PACUtils::_ is callable by fully-qualified name - the
#    exact call style PAC::Theme::Widget uses. Loading the whole module here is
#    avoided on purpose: it pulls `use Gtk3 '-init'`, which aborts the process
#    when no display is present. End-to-end launch is covered by the QEMU
#    Ubuntu 26.04 run recorded on the fix PR.
my ($install) = $utils =~ /(\*PACUtils::_\s*=\s*sub\s*\{.*?\};)/s;
ok($install, 'found the typeglob install statement in PACUtils.pm');
eval $install;                                          ## no critic (StringyEval)
is($@, '', 'install statement evaluates cleanly');
ok(defined &PACUtils::_, '&PACUtils::_ is a real, defined symbol');

{
    package T::FakeGlade;
    sub get_object { return "obj:$_[1]" }
}
my $self = { _GLADE => bless({}, 'T::FakeGlade') };
is(PACUtils::_($self, 'someWidget'), 'obj:someWidget',
    'fully-qualified PACUtils::_ resolves a widget by name');

done_testing();
