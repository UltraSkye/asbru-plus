#!/usr/bin/perl
# t/05-workflow-lint.t — Validate GitHub Actions workflow files
use strict;
use warnings;
use Test::More;
use File::Find;

my $wf_dir = '.github/workflows';

unless (-d $wf_dir) {
    plan skip_all => '.github/workflows not present (excluded from build context?)';
}

my @workflows;
find(sub { push @workflows, $File::Find::name if /\.yml$/ }, $wf_dir);
@workflows = sort @workflows;

if (!@workflows) {
    plan skip_all => 'No workflow YAML files found';
}

plan tests => scalar(@workflows) * 5;

for my $wf (@workflows) {
    open my $fh, '<', $wf or BAIL_OUT("Cannot open $wf: $!");
    my $content = do { local $/; <$fh> };
    close $fh;

    like($content, qr/^on:/m,   "$wf: has 'on:' trigger");
    like($content, qr/^jobs:/m, "$wf: has 'jobs:' section");

    unlike($content,
        qr/asbru-cm\/asbru-cm\.git/,
        "$wf: does not reference upstream repo URL");

    # No deleted files referenced
    unlike($content, qr/build\.sh\b/,
        "$wf: does not reference deleted build.sh");

    # All actions pinned to v4+ (no deprecated v1/v2/v3)
    unlike($content, qr/uses:\s+actions\/\w+\@v[123]\b/,
        "$wf: no deprecated actions v1/v2/v3");
}
