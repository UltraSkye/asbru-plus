#!/usr/bin/perl
# t/44-theme-image.t — PAC::Theme::Image bundle.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $img_pm = "$RealBin/../lib/PAC/Theme/Image.pm";
ok(-r $img_pm, 'PAC/Theme/Image.pm exists');

my $src = do {
    open my $f, '<', $img_pm or die "open: $!";
    local $/; <$f>;
};

# Package + 4 public functions
like($src, qr/^package PAC::Theme::Image;/m, 'declares package');
like($src, qr/^sub screenshot\b/m,        'has screenshot');
like($src, qr/^sub scale\b/m,             'has scale');
like($src, qr/^sub pixbuf_from_file\b/m,  'has pixbuf_from_file');
like($src, qr/^sub banner\b/m,            'has banner');

# scale uses Gdk::Pixbuf properly + has aspect-ratio branch
like($src, qr/Gtk3::Gdk::Pixbuf->new_from_file/, 'scale loads via Gdk::Pixbuf');
like($src, qr/scale_simple\(\$w, \$h, 'GDK_INTERP_HYPER'\)/,
    'scale uses GDK_INTERP_HYPER');

# banner reads $PACUtils::THEME_DIR (replaced the legacy lexical $THEME_DIR)
like($src, qr/\$PACUtils::THEME_DIR/, 'banner reads $PACUtils::THEME_DIR');
unlike($src, qr/\$THEME_DIR(?!::)/m,
    'no bare $THEME_DIR (would be undef-from-outside)') or do {
        diag("banner() must use \$PACUtils::THEME_DIR, not the legacy lexical");
    };

# PACUtils proxies wired
my $utils = do {
    open my $f, '<', "$RealBin/../lib/PACUtils.pm" or die "open: $!";
    local $/; <$f>;
};
like($utils, qr/^require PAC::Theme::Image/m, 'PACUtils requires PAC::Theme::Image');
for my $pair (
    [_screenshot      => 'screenshot'],
    [_scale           => 'scale'],
    [_pixBufFromFile  => 'pixbuf_from_file'],
    [_createBanner    => 'banner'],
) {
    my ($legacy, $new) = @$pair;
    like($utils,
        qr/sub \Q$legacy\E\s*\{\s*goto\s*&PAC::Theme::Image::\Q$new\E\s*;\s*\}/,
        "$legacy is goto-proxy to $new");
}

# Eval-protected loading (no bare die that escapes)
like($src, qr/eval\s*\{\s*\$pb\s*=\s*Gtk3::Gdk::Pixbuf->new_from_file/s,
    'pixbuf load is eval-protected');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
for my $sub (qw(screenshot scale pixbuf_from_file banner)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item $sub");
}

done_testing();
