use strict;
use warnings;

use File::Spec;
use FindBin;
use Test::More;

my $root = File::Spec->catdir($FindBin::Bin, '..');

my %gitignore = map { $_ => 1 } _read_lines(File::Spec->catfile($root, '.gitignore'));
my %manifest_skip = map { $_ => 1 } _read_lines(File::Spec->catfile($root, 'MANIFEST.SKIP'));

for my $line (
  qw(
    .plx/
    local/
    _eumm/
    blib/
    Makefile
    MYMETA.json
    MYMETA.yml
    pm_to_blib
    pm_to_blib.ts
    .DS_Store
    *.swp
    *~
    *.orig
    *.rej
  )
) {
  ok $gitignore{$line}, ".gitignore includes $line";
}

for my $line (
  '^\.git/',
  '^\.plx/',
  '^local/',
  '^_eumm/',
  '^blib/',
  '^Makefile$',
  '^MYMETA\.json$',
  '^MYMETA\.yml$',
  '^pm_to_blib(?:\.ts)?$',
  '(?:^|/)\.DS_Store$',
  '(?:^|/).*\.swp$',
  '(?:^|/).*~$',
  '(?:^|/).*\.orig$',
  '(?:^|/).*\.rej$',
) {
  ok $manifest_skip{$line}, "MANIFEST.SKIP includes $line";
}

done_testing;

sub _read_lines {
  my ($path) = @_;
  open my $fh, '<', $path or die "open $path: $!";
  chomp(my @lines = <$fh>);
  return grep { length && $_ !~ /\A#/ } @lines;
}
