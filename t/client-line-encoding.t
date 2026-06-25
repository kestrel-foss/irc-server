use strict;
use warnings;

use Test::More;

use Overnet::Program::IRC::Server;

pipe(my $reader, my $writer)
  or die "pipe failed: $!";

my $server = Overnet::Program::IRC::Server->new;
$server->{clients}{'client-1'} = {
  id           => 'client-1',
  socket       => $writer,
  capabilities => {},
};

my $wide_marker = chr(0x1f702);

ok(
  $server->_send_client_line('client-1', ':seven3 PRIVMSG #overnet :hello kestrel ' . $wide_marker),
  'wide-character IRC line is written',
);

my $payload = '';
sysread($reader, $payload, 1024);

is(
  unpack('H*', $payload),
  unpack('H*', ":seven3 PRIVMSG #overnet :hello kestrel ")
    . 'f09f9c82'
    . unpack('H*', "\r\n"),
  'IRC line is encoded as UTF-8 bytes before syswrite',
);

done_testing;
