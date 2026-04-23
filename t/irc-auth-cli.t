use strict;
use warnings;

use File::Spec;
use FindBin;
use Test::More;

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-irc-auth.pl');

ok -f $script, 'auth helper script exists'
  or BAIL_OUT('overnet-irc-auth.pl is required');

my $output = qx{$^X "$script" --help 2>&1};
my $exit = $? >> 8;

is $exit, 0, '--help exits successfully';
like $output, qr/overnet-irc-auth\.pl bridge \[options\]/,
  'usage includes bridge mode';
like $output, qr/--line IRC_NOTICE_LINE/,
  'usage documents explicit single-line bridge mode';
like $output, qr/stdin/i,
  'usage documents continuous stdin bridge mode';
like $output, qr/SASL/i,
  'usage documents SASL bridge support';
like $output, qr/AUTHENTICATE/,
  'usage documents AUTHENTICATE challenge handling';

done_testing;
