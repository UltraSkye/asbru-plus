#!/usr/bin/perl
# t/53-theme-switch.t — PAC::Theme::Switch surface check.

use strict;
use warnings;
use Test::More;
use FindBin qw($RealBin);

my $sw = "$RealBin/../lib/PAC/Theme/Switch.pm";
ok(-r $sw, 'PAC/Theme/Switch.pm exists');

my $src = do {
    open my $f, '<', $sw or die "open: $!";
    local $/; <$f>;
};

# Package + 3 public functions
like($src, qr/^package PAC::Theme::Switch;/m, 'declares package');
like($src, qr/^sub toggle\b/m,         'has toggle');
like($src, qr/^sub reset_style\b/m,    'has reset_style');
like($src, qr/^sub refresh_images\b/m, 'has refresh_images');

# Theme persistence path
like($src, qr/PAC::Vault::cipher_cfg/,    'persists via PAC::Vault::cipher_cfg');
like($src, qr/PAC::Vault::decipher_cfg/,  'restores after persist');
like($src, qr/PAC::Crypto::HMAC::write_for/, 'updates HMAC sidecar after save');
like($src, qr/nstore/,                    'uses nstore for save');

# Theme switch state
like($src, qr/asbru-dark/, 'mentions asbru-dark theme');
like($src, qr/_THEME_PROVIDERS_BY_NAME/, 'tracks providers by name');
like($src, qr/StyleContext::add_provider_for_screen/, 'adds CSS provider');
like($src, qr/gtk-application-prefer-dark-theme/, 'flips prefer-dark hint');

# Pixbuf reload via PAC::Theme::Image
like($src, qr/PAC::Theme::Image::pixbuf_from_file/,
    'reloads pixbufs via PAC::Theme::Image');
like($src, qr/PAC::Theme::Icons::register/,
    're-registers icon factory after switch');

# References to PACMain package vars (post-promotion to 'our')
like($src, qr/\$PACMain::THEME_DIR/, 'reads $PACMain::THEME_DIR');
like($src, qr/\$PACMain::RES_DIR/,   'reads $PACMain::RES_DIR');
like($src, qr/\$PACMain::CFG_FILE_NFREEZE/, 'reads $PACMain::CFG_FILE_NFREEZE');
like($src, qr/\$PACMain::GROUPICON_ROOT/, 'mutates $PACMain::GROUPICON_ROOT');

# PACMain wrappers
my $main = do {
    open my $f, '<', "$RealBin/../lib/PACMain.pm" or die "open: $!";
    local $/; <$f>;
};
like($main, qr/^require PAC::Theme::Switch/m, 'PACMain requires PAC::Theme::Switch');
like($main, qr/sub _toggleTheme \{[^}]*PAC::Theme::Switch::toggle/s,
    '_toggleTheme wrapper calls toggle');
like($main, qr/sub _resetStyleRecursively\s*\{\s*goto\s*&PAC::Theme::Switch::reset_style/,
    '_resetStyleRecursively is goto-proxy');
like($main, qr/sub _refreshImagesRecursively\s*\{\s*goto\s*&PAC::Theme::Switch::refresh_images/,
    '_refreshImagesRecursively is goto-proxy');

# PACMain promoted lexicals to 'our'
like($main, qr/^our \$RES_DIR\s*=/m,    '$RES_DIR is "our"');
like($main, qr/^our \$THEME_DIR\s*=/m,  '$THEME_DIR is "our"');
like($main, qr/^our \$CFG_FILE_NFREEZE\s*=/m, '$CFG_FILE_NFREEZE is "our"');
like($main, qr/^our \$GROUPICON_ROOT;/m, '$GROUPICON_ROOT is "our"');

# POD
like($src, qr/^=head1 NAME/m,       'POD: NAME');
like($src, qr/^=head1 PUBLIC API/m, 'POD: PUBLIC API');
for my $sub (qw(toggle reset_style refresh_images)) {
    like($src, qr/^=item \Q$sub\E\b/m, "POD =item $sub");
}

done_testing();
