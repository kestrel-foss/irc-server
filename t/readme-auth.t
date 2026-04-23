use strict;
use warnings;

use File::Spec;
use FindBin;
use Test::More;

my $readme = File::Spec->catfile($FindBin::Bin, '..', 'README.md');

ok -f $readme, 'README exists'
  or BAIL_OUT('README.md is required');

open my $fh, '<', $readme
  or die "open $readme failed: $!";
my $content = do { local $/; <$fh> };
close $fh
  or die "close $readme failed: $!";

like $content, qr/OVERNET_AUTH_SOCK/,
  'README documents OVERNET_AUTH_SOCK for auth-agent discovery';
like $content, qr/--auth-sock/,
  'README documents the explicit auth socket override';
like $content, qr/overnet-irc-auth\.pl auth/,
  'README documents the IRC auth helper';
like $content, qr/overnet-auth-agent\.pl --config-file/,
  'README documents starting the auth-agent daemon before IRC auth';

done_testing;
