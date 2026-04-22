use strict;
use warnings;

use File::Spec;
use FindBin;
use Test::More;

my @scripts = (
  'bin/overnet-irc-authority-relay-service.pl',
  'bin/overnet-irc-authority-relay.pl',
  'bin/overnet-irc-chat-client.pl',
  'bin/overnet-irc-local-server.pl',
  'bin/overnet-irc-server.pl',
  'bin/overnet-irc-service.pl',
);

plan tests => scalar @scripts;

for my $script (@scripts) {
  my $path = File::Spec->catfile($FindBin::Bin, '..', split m{/}, $script);
  my $ok = system($^X, '-c', $path) == 0;
  ok $ok, "$script compiles";
}
