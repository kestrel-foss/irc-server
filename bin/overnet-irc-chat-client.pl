#!/usr/bin/env perl
use strict;
use warnings;
use IO::Handle ();
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL qw(SSL_VERIFY_NONE SSL_VERIFY_PEER);
use Getopt::Long qw(GetOptions);

my %options = (
  host      => '127.0.0.1',
  port      => 16667,
  channel   => '#overnet',
  realname  => 'Overnet IRC Demo User',
  auto_join => 1,
  tls       => 0,
  tls_min_version => 'TLSv1.2',
);
my $help = 0;

GetOptions(
  'host=s'      => \$options{host},
  'port=i'      => \$options{port},
  'nick=s'      => \$options{nick},
  'username=s'  => \$options{username},
  'realname=s'  => \$options{realname},
  'channel=s'   => \$options{channel},
  'auto-join!'  => \$options{auto_join},
  'tls!'        => \$options{tls},
  'tls-no-verify!' => \$options{tls_no_verify},
  'tls-ca-file=s' => \$options{tls_ca_file},
  'tls-server-name=s' => \$options{tls_server_name},
  'tls-min-version=s' => \$options{tls_min_version},
  'help'        => \$help,
) or die _usage();

if ($help) {
  print _usage();
  exit 0;
}

die "--nick is required\n"
  unless defined $options{nick} && length $options{nick};
die "--port must be between 0 and 65535\n"
  unless defined $options{port}
    && !ref($options{port})
    && $options{port} =~ /\A(?:0|[1-9]\d{0,4})\z/
    && $options{port} <= 65535;

$options{username} = $options{nick}
  unless defined $options{username} && length $options{username};

my $socket = !$options{tls}
  ? IO::Socket::INET->new(
      PeerHost => $options{host},
      PeerPort => $options{port},
      Proto    => 'tcp',
      Timeout  => 3,
    )
  : IO::Socket::SSL->new(
      PeerHost        => $options{host},
      PeerPort        => $options{port},
      Timeout         => 3,
      SSL_verify_mode => $options{tls_no_verify} ? SSL_VERIFY_NONE() : SSL_VERIFY_PEER(),
      (defined $options{tls_ca_file} && length($options{tls_ca_file})
        ? (SSL_ca_file => $options{tls_ca_file})
        : ()),
      (SSL_hostname => (
        defined $options{tls_server_name} && length($options{tls_server_name})
          ? $options{tls_server_name}
          : $options{host}
      )),
      (defined $options{tls_min_version}
        ? (SSL_version => _ssl_version_for_min_version($options{tls_min_version}))
        : ()),
    );
die(
  $options{tls}
    ? "Can't connect TLS to $options{host}:$options{port}: " . IO::Socket::SSL::errstr() . "\n"
    : "Can't connect to $options{host}:$options{port}: $!\n"
) unless $socket;

binmode($socket, ':raw');
binmode(STDIN, ':raw');
binmode(STDOUT, ':raw');
$socket->autoflush(1);
STDOUT->autoflush(1);

my $selector = IO::Select->new($socket, \*STDIN);
my $socket_buffer = '';
my $done = 0;
my $registered = 0;
my $auto_join_sent = 0;
my $current_target = $options{channel};

print "Connected to $options{host}:$options{port}" . ($options{tls} ? ' over TLS' : '') . " as $options{nick}\n";
print "Plain text sends to $current_target\n" if $options{auto_join};
print "Type /help for commands.\n";

_send_line($socket, 'CAP END');
_send_line($socket, 'NICK ' . $options{nick});
_send_line($socket, sprintf('USER %s 0 * :%s', $options{username}, $options{realname}));

while (!$done) {
  my @ready = $selector->can_read(0.1);
  next unless @ready;

  for my $handle (@ready) {
    if (defined fileno($handle) && fileno($handle) == fileno($socket)) {
      my $bytes = sysread($socket, my $chunk, 4096);
      die "Server disconnected\n"
        unless defined $bytes && $bytes > 0;

      $socket_buffer .= $chunk;
      while ($socket_buffer =~ s/\A([^\n]*\n)//) {
        my $line = $1;
        $line =~ s/\r?\n\z//;
        next unless length $line;
        $done = _handle_server_line(
          socket         => $socket,
          line           => $line,
          registered_ref => \$registered,
          auto_join      => $options{auto_join},
          auto_join_sent => \$auto_join_sent,
          channel        => $options{channel},
        );
        last if $done;
      }
      next;
    }

    my $input = <STDIN>;
    if (!defined $input) {
      _send_line($socket, 'QUIT :stdin closed');
      $done = 1;
      last;
    }

    $input =~ s/\r?\n\z//;
    next unless length $input;
    my $handled = eval {
      _handle_user_input(
        socket         => $socket,
        input          => $input,
        current_target => \$current_target,
        done           => \$done,
      );
    };
    if (!$handled) {
      my $error = $@ || "unknown client input error\n";
      chomp $error;
      print STDERR "error: $error\n";
      next;
    }
    next;
  }
}

close $socket;
exit 0;

sub _handle_server_line {
  my (%args) = @_;
  my $socket = $args{socket};
  my $line = $args{line};
  my $registered_ref = $args{registered_ref};
  my $auto_join_sent = $args{auto_join_sent};

  if ($line =~ /\APING :(.*)\z/i) {
    _send_line($socket, 'PONG :' . $1);
    return 0;
  }

  if ($line =~ /\A:\S+\s+001\s+/) {
    $$registered_ref = 1;
    if ($args{auto_join} && !$$auto_join_sent && defined $args{channel} && length $args{channel}) {
      _send_line($socket, 'JOIN ' . $args{channel});
      $$auto_join_sent = 1;
    }
  }

  print _format_server_line($line), "\n";
  return 0;
}

sub _handle_user_input {
  my (%args) = @_;
  my $socket = $args{socket};
  my $input = $args{input};
  my $current_target_ref = $args{current_target};
  my $done_ref = $args{done};

  if ($input =~ m{\A/help\z}) {
    print _help_text();
    return 1;
  }

  if ($input =~ m{\A/join\s+(\S+)\z}) {
    $$current_target_ref = $1;
    _send_line($socket, 'JOIN ' . $1);
    return 1;
  }

  if ($input =~ m{\A/target\s+(\S+)\z}) {
    $$current_target_ref = $1;
    print "Current target set to $1\n";
    return 1;
  }

  if ($input =~ m{\A/msg\s+(\S+)\s+(.+)\z}) {
    _send_line($socket, sprintf('PRIVMSG %s :%s', $1, $2));
    return 1;
  }

  if ($input =~ m{\A/notice\s+(\S+)\s+(.+)\z}) {
    _send_line($socket, sprintf('NOTICE %s :%s', $1, $2));
    return 1;
  }

  if ($input =~ m{\A/topic\s+(\S+)\s+(.+)\z}) {
    _send_line($socket, sprintf('TOPIC %s :%s', $1, $2));
    return 1;
  }

  if ($input =~ m{\A/names(?:\s+(\S+))?\z}) {
    my $target = defined $1 ? $1 : $$current_target_ref;
    die "No current target for /names\n"
      unless defined $target && length $target;
    _send_line($socket, 'NAMES ' . $target);
    return 1;
  }

  if ($input =~ m{\A/part(?:\s+(\S+))?(?:\s+(.+))?\z}) {
    my $target = defined $1 ? $1 : $$current_target_ref;
    die "No current target for /part\n"
      unless defined $target && length $target;
    my $line = 'PART ' . $target;
    $line .= ' :' . $2 if defined $2 && length $2;
    _send_line($socket, $line);
    return 1;
  }

  if ($input =~ m{\A/nick\s+(\S+)\z}) {
    _send_line($socket, 'NICK ' . $1);
    return 1;
  }

  if ($input =~ m{\A/raw\s+(.+)\z}) {
    _send_line($socket, $1);
    return 1;
  }

  if ($input =~ m{\A/quit(?:\s+(.+))?\z}) {
    my $reason = defined $1 ? $1 : 'client quit';
    _send_line($socket, 'QUIT :' . $reason);
    $$done_ref = 1;
    return 1;
  }

  die "No current target. Use /join, /msg, or /target first.\n"
    unless defined $$current_target_ref && length $$current_target_ref;

  _send_line($socket, sprintf('PRIVMSG %s :%s', $$current_target_ref, $input));
  return 1;
}

sub _format_server_line {
  my ($line) = @_;

  if ($line =~ /\A:([^ ]+)\s+PRIVMSG\s+(\S+)\s+:(.*)\z/) {
    return sprintf('<%s -> %s> %s', $1, $2, $3);
  }

  if ($line =~ /\A:([^ ]+)\s+NOTICE\s+(\S+)\s+:(.*)\z/) {
    return sprintf('-%s -> %s- %s', $1, $2, $3);
  }

  if ($line =~ /\A:([^ ]+)\s+JOIN\s+(\S+)\z/) {
    return sprintf('* %s joined %s', $1, $2);
  }

  if ($line =~ /\A:([^ ]+)\s+PART\s+(\S+)(?:\s+:(.*))?\z/) {
    return defined $3 && length $3
      ? sprintf('* %s left %s (%s)', $1, $2, $3)
      : sprintf('* %s left %s', $1, $2);
  }

  if ($line =~ /\A:([^ ]+)\s+QUIT(?:\s+:(.*))?\z/) {
    return defined $2 && length $2
      ? sprintf('* %s quit (%s)', $1, $2)
      : sprintf('* %s quit', $1);
  }

  if ($line =~ /\A:([^ ]+)\s+TOPIC\s+(\S+)\s+:(.*)\z/) {
    return sprintf('* %s changed the topic on %s to: %s', $1, $2, $3);
  }

  if ($line =~ /\A:\S+\s+353\s+\S+\s+=\s+(\S+)\s+:(.*)\z/) {
    return sprintf('* names for %s: %s', $1, $2);
  }

  return $line;
}

sub _send_line {
  my ($socket, $line) = @_;

  my $payload = $line . "\r\n";
  my $offset = 0;
  while ($offset < length $payload) {
    my $written = syswrite($socket, $payload, length($payload) - $offset, $offset);
    die "Failed to write IRC line: $!\n"
      unless defined $written;
    $offset += $written;
  }

  return 1;
}

sub _help_text {
  return <<'HELP';
Commands:
  /help                     Show this help
  /join #channel            Join a channel and make it the current target
  /target <target>          Set the current target for plain text
  /msg <target> <text>      Send a direct message or channel message
  /notice <target> <text>   Send a notice
  /topic <channel> <text>   Set the topic on a joined channel
  /names [channel]          Ask the server for the current names list
  /part [channel] [reason]  Leave a channel
  /nick <newnick>           Change your nick
  /raw <line>               Send a raw IRC line
  /quit [reason]            Quit the client

Plain text sends a PRIVMSG to the current target.
HELP
}

sub _usage {
  return <<'USAGE';
Usage:
  perl irc-server/bin/overnet-irc-chat-client.pl --nick NICK [options]

Options:
  --host HOST        IRC server host (default: 127.0.0.1)
  --port PORT        IRC server port (default: 16667)
  --nick NICK        Nickname to register with
  --username NAME    IRC USER field (default: same as nick)
  --realname NAME    IRC realname field (default: Overnet IRC Demo User)
  --channel NAME     Auto-join this channel after 001 (default: #overnet)
  --auto-join        Auto-join the initial channel (default)
  --no-auto-join     Do not auto-join on connect
  --tls              Connect to the IRC server over TLS
  --tls-no-verify    Skip TLS certificate verification for local self-signed demos
  --tls-ca-file PATH Trust this CA bundle/file for TLS verification
  --tls-server-name NAME
                     Expected server name for TLS hostname verification
  --tls-min-version NAME
                     TLS minimum version (default: TLSv1.2)
  --help             Show this message
USAGE
}

sub _ssl_version_for_min_version {
  my ($min_version) = @_;

  return 'SSLv23:!SSLv3:!SSLv2:!TLSv1:!TLSv1_1'
    if $min_version eq 'TLSv1.2';
  return 'TLSv1_3'
    if $min_version eq 'TLSv1.3';

  die "Unsupported --tls-min-version: $min_version\n";
}
