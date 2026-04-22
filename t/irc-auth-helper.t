use strict;
use warnings;

use File::Temp qw(tempfile);
use File::Spec;
use FindBin;
use JSON::PP qw(decode_json);
use MIME::Base64 qw(decode_base64);
use Net::Nostr::Key;
use Test::More;

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-irc-auth.pl');

sub _run_command {
  my (%args) = @_;
  my @command = @{$args{command} || []};
  my $stdin_text = $args{stdin};

  my ($stdin_fh, $stdin_path) = tempfile();
  if (defined $stdin_text) {
    print {$stdin_fh} $stdin_text;
  }
  close $stdin_fh;

  my ($stderr_fh, $stderr_path) = tempfile();
  close $stderr_fh;

  my $command_text = join(' ', map { _shell_quote($_) } _perl_command(@command));
  $command_text .= ' < ' . _shell_quote($stdin_path);
  $command_text .= ' 2> ' . _shell_quote($stderr_path);

  open my $stdout, '-|', 'sh', '-c', $command_text
    or die "open stdout pipe failed: $!";
  local $/;
  my $captured_stdout = <$stdout>;
  close $stdout;
  my $exit = $? >> 8;

  return {
    exit_code => $exit,
    stdout    => $captured_stdout,
    stderr    => _slurp_file($stderr_path),
  };
}

sub _perl_command {
  my (@command) = @_;
  return (
    $^X,
    map(('-I', $_), grep { defined($_) && !ref($_) && length($_) } @INC),
    @command,
  );
}

sub _slurp_file {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "open $path failed: $!";
  local $/;
  my $contents = <$fh>;
  close $fh;
  return $contents;
}

sub _shell_quote {
  my ($value) = @_;
  return "''"
    unless defined $value && length $value;
  $value =~ s/'/'\\''/g;
  return "'$value'";
}

subtest 'auth mode emits a paste-ready OVERNETAUTH AUTH line' => sub {
  my $key = Net::Nostr::Key->new;
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope = 'irc://irc.example.test/overnet';

  my $result = _run_command(
    command => [
      $script,
      'auth',
      '--privkey-secret', $key->privkey_hex,
      '--challenge', $challenge,
      '--scope', $scope,
      '--created-at', '1744301000',
    ],
  );
  is $result->{exit_code}, 0, 'the helper exits successfully';
  is $result->{stderr}, '', 'the helper does not write to stderr';
  chomp(my $stdout = $result->{stdout});

  my ($payload) = $stdout =~ qr{\A/quote OVERNETAUTH AUTH (\S+)\z};
  ok defined $payload, 'the helper prints a paste-ready OVERNETAUTH AUTH command';
  my $event = decode_json(decode_base64($payload));

  is $event->{kind}, 22242, 'the encoded auth event uses kind 22242';
  is $event->{created_at}, 1744301000, 'the encoded auth event preserves the requested timestamp';
  is $event->{content}, '', 'the encoded auth event uses an empty content payload';
  is_deeply $event->{tags}, [
    [ relay => $scope ],
    [ challenge => $challenge ],
  ], 'the encoded auth event includes the expected relay scope and challenge tags';
  like $event->{pubkey}, qr/\A[0-9a-f]{64}\z/, 'the encoded auth event includes a Nostr pubkey';
  like $event->{sig}, qr/\A[0-9a-f]{128}\z/, 'the encoded auth event includes a Nostr signature';
};

subtest 'delegate mode accepts stdin secrets and emits a paste-ready OVERNETAUTH DELEGATE line' => sub {
  my $key = Net::Nostr::Key->new;
  my $result = _run_command(
    command => [
      $script,
      'delegate',
      '--privkey-stdin',
      '--relay-url', 'ws://127.0.0.1:7448',
      '--scope', 'irc://irc.example.test/overnet',
      '--delegate-pubkey', ('d' x 64),
      '--session-id', 'session-123',
      '--expires-at', '1744304600',
      '--created-at', '1744301100',
    ],
    stdin => $key->privkey_nsec . "\n",
  );
  is $result->{exit_code}, 0, 'the helper exits successfully';
  is $result->{stderr}, '', 'the helper does not write to stderr';
  chomp(my $stdout_text = $result->{stdout});

  my ($payload) = $stdout_text =~ qr{\A/quote OVERNETAUTH DELEGATE (\S+)\z};
  ok defined $payload, 'the helper prints a paste-ready OVERNETAUTH DELEGATE command';
  my $event = decode_json(decode_base64($payload));

  is $event->{kind}, 14142, 'the encoded delegation event uses kind 14142';
  is $event->{created_at}, 1744301100, 'the encoded delegation event preserves the requested timestamp';
  is $event->{content}, '', 'the encoded delegation event uses an empty content payload';
  is_deeply $event->{tags}, [
    [ relay => 'ws://127.0.0.1:7448' ],
    [ server => 'irc://irc.example.test/overnet' ],
    [ delegate => ('d' x 64) ],
    [ session => 'session-123' ],
    [ expires_at => '1744304600' ],
  ], 'the encoded delegation event includes the expected relay, scope, delegate, session, and expiration tags';
  like $event->{pubkey}, qr/\A[0-9a-f]{64}\z/, 'the encoded delegation event includes a Nostr pubkey';
  like $event->{sig}, qr/\A[0-9a-f]{128}\z/, 'the encoded delegation event includes a Nostr signature';
};

done_testing;
