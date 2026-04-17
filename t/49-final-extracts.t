#!/usr/bin/perl
# t/49-final-extracts.t — surface checks for the P3/20-22 extractions:
#   PAC::Util::ShellEscape, PAC::Theme::Widget, PAC::Net::WindowList.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";

# ── PAC::Util::ShellEscape — runtime check (pure-Perl, no deps) ─────
require_ok('PAC::Util::ShellEscape');
can_ok('PAC::Util::ShellEscape', 'escape');

is(PAC::Util::ShellEscape::escape('hello'), 'hello', 'plain text untouched');
is(PAC::Util::ShellEscape::escape('a$b'),    'a\\$b', 'escapes $');
is(PAC::Util::ShellEscape::escape('a"b'),    'a\\"b', 'escapes "');
is(PAC::Util::ShellEscape::escape('a`b'),    'a\\`b', 'escapes backtick');
is(PAC::Util::ShellEscape::escape('a\\b'),   'a\\\\b','escapes backslash');
is(PAC::Util::ShellEscape::escape('a!b'),    'a\\!b', 'escapes !');
is(PAC::Util::ShellEscape::escape("a\nb"),   'a\\nb', 'newline -> literal \\n');
is(PAC::Util::ShellEscape::escape("a\rb"),   'a\\rb', 'CR -> literal \\r');
is(PAC::Util::ShellEscape::escape(undef),    '',      'undef -> empty');

# ── PAC::Theme::Widget — source-only checks (Gtk needed at runtime) ─
my $widget_src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Theme/Widget.pm" or die "open: $!";
    local $/; <$f>;
};
like($widget_src, qr/^package PAC::Theme::Widget;/m, 'Widget: package');
for my $sub (qw(update_color set_default_rgba set_window_paintable draw_callback)) {
    like($widget_src, qr/^sub \Q$sub\E\b/m, "Widget: has $sub");
}
like($widget_src, qr/my \(\$R, \$G, \$B, \$A\)/, 'Widget: RGBA state is module-lexical');
like($widget_src, qr/PACUtils::_\(\$self, \$widget\)/, 'Widget: uses PACUtils::_ to resolve widget');

# ── PAC::Net::WindowList — source-only (Wnck needed at runtime) ─────
my $wnck_src = do {
    open my $f, '<', "$RealBin/../lib/PAC/Net/WindowList.pm" or die "open: $!";
    local $/; <$f>;
};
like($wnck_src, qr/^package PAC::Net::WindowList;/m, 'WindowList: package');
like($wnck_src, qr/^sub all\b/m, 'WindowList: has all');
like($wnck_src, qr/Wnck::Screen::get_default/, 'WindowList: uses Wnck::Screen');
like($wnck_src, qr/by_xid.*by_name|by_name.*by_xid/s,
    'WindowList: indexes by both xid and name');

# ── PACUtils proxies wired ──────────────────────────────────────────
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Util::ShellEscape/m, 'requires Util::ShellEscape');
like($utils, qr/^require PAC::Theme::Widget/m,     'requires Theme::Widget');
like($utils, qr/^require PAC::Net::WindowList/m,   'requires Net::WindowList');

for my $pair (
    [_doShellEscape       => 'PAC::Util::ShellEscape::escape'],
    [_updateWidgetColor   => 'PAC::Theme::Widget::update_color'],
    [_setDefaultRGBA      => 'PAC::Theme::Widget::set_default_rgba'],
    [_setWindowPaintable  => 'PAC::Theme::Widget::set_window_paintable'],
    [mydraw               => 'PAC::Theme::Widget::draw_callback'],
    [_getXWindowsList     => 'PAC::Net::WindowList::all'],
) {
    my ($legacy, $target) = @$pair;
    like($utils,
        qr/sub \Q$legacy\E\s*\{\s*goto\s*&\Q$target\E\s*;\s*\}/,
        "$legacy is goto-proxy to $target");
}

# Old RGBA lexical removed
unlike($utils, qr/^my \(\$R,\$G,\$B,\$A\);/m,
    'PACUtils no longer holds (\$R,\$G,\$B,\$A) lexical');

# POD presence
for my $pair (
    ['lib/PAC/Util/ShellEscape.pm', 'escape'],
    ['lib/PAC/Theme/Widget.pm',     'update_color'],
    ['lib/PAC/Net/WindowList.pm',   'all'],
) {
    my ($file, $sub) = @$pair;
    my $src = do { open my $f, '<', "$RealBin/../$file" or die; local $/; <$f> };
    like($src, qr/^=head1 NAME/m,       "$file: POD NAME");
    like($src, qr/^=head1 PUBLIC API/m, "$file: POD PUBLIC API");
    like($src, qr/^=item \Q$sub\E\b/m,  "$file: POD =item $sub");
}

done_testing();
