#!/usr/bin/env perl
use strict;
use warnings;

use Cwd qw(abs_path);
use File::Basename qw(dirname);
use File::Path qw(make_path);
use File::Spec;
use FindBin;
use Getopt::Long qw(GetOptions);
use JSON::PP ();
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../../overnet-code/lib";
use lib "$FindBin::Bin/../../overnet-code/local/lib/perl5";
use IO::Socket::SSL::Utils qw(CERT_create PEM_cert2file PEM_key2file);

use Overnet::Core::Nostr;
use Overnet::Program::Host;
use Overnet::Program::Runtime;

my %options = (
  adapter_id       => 'irc.service',
  network          => 'overnet',
  listen_host      => '127.0.0.1',
  listen_port      => 16667,
  server_name      => 'irc.overnet.local',
  tls              => 0,
  tls_min_version  => 'TLSv1.2',
);
my @channel_group_args;
my $health_file;
my $log_file;
my $help = 0;

GetOptions(
  'adapter-id=s'                  => \$options{adapter_id},
  'network=s'                     => \$options{network},
  'listen-host=s'                 => \$options{listen_host},
  'listen-port=i'                 => \$options{listen_port},
  'server-name=s'                 => \$options{server_name},
  'signing-key-file=s'            => \$options{signing_key_file},
  'group-host=s'                  => \$options{group_host},
  'channel-group=s'               => \@channel_group_args,
  'authority-relay-url=s'         => \$options{authority_relay_url},
  'authority-relay-query-timeout-ms=i' => \$options{authority_relay_query_timeout_ms},
  'authority-relay-poll-interval-ms=i' => \$options{authority_relay_poll_interval_ms},
  'tls!'                          => \$options{tls},
  'tls-cert-chain-file=s'         => \$options{tls_cert_chain_file},
  'tls-private-key-file=s'        => \$options{tls_private_key_file},
  'tls-ca-file=s'                 => \$options{tls_ca_file},
  'tls-min-version=s'             => \$options{tls_min_version},
  'tls-verify-peer!'              => \$options{tls_verify_peer},
  'health-file=s'                 => \$health_file,
  'log-file=s'                    => \$log_file,
  'help'                          => \$help,
) or die _usage();

if ($help) {
  print _usage();
  exit 0;
}

die "listen-port must be between 0 and 65535\n"
  unless defined $options{listen_port}
    && !ref($options{listen_port})
    && $options{listen_port} =~ /\A(?:0|[1-9]\d{0,4})\z/
    && $options{listen_port} <= 65535;

my $signing_key_file = defined $options{signing_key_file} && length $options{signing_key_file}
  ? $options{signing_key_file}
  : File::Spec->catfile(_default_state_dir(), 'service-signing-key.pem');
_ensure_signing_key($signing_key_file);

my $tls_config;
if ($options{tls}) {
  my $tls_cert_chain_file = defined $options{tls_cert_chain_file} && length $options{tls_cert_chain_file}
    ? $options{tls_cert_chain_file}
    : File::Spec->catfile(_default_state_dir(), 'service-tls-cert.pem');
  my $tls_private_key_file = defined $options{tls_private_key_file} && length $options{tls_private_key_file}
    ? $options{tls_private_key_file}
    : File::Spec->catfile(_default_state_dir(), 'service-tls-key.pem');

  _ensure_tls_material(
    cert_chain_file  => $tls_cert_chain_file,
    private_key_file => $tls_private_key_file,
    listen_host      => $options{listen_host},
  );

  $tls_config = {
    enabled          => 1,
    mode             => 'server',
    cert_chain_file  => $tls_cert_chain_file,
    private_key_file => $tls_private_key_file,
    min_version      => $options{tls_min_version},
  };
  $tls_config->{verify_peer} = $options{tls_verify_peer} ? 1 : 0
    if defined $options{tls_verify_peer};
  $tls_config->{ca_file} = $options{tls_ca_file}
    if defined $options{tls_ca_file} && length $options{tls_ca_file};
}

my $adapter_config = {};
$adapter_config->{group_host} = $options{group_host}
  if defined $options{group_host} && length $options{group_host};
if (@channel_group_args) {
  $adapter_config->{channel_groups} = {
    map {
      die "--channel-group must be CHANNEL=GROUP_ID\n"
        unless /\A([^=]+)=(.+)\z/;
      ($1 => $2)
    } @channel_group_args
  };
}

my $authority_relay;
if (defined $options{authority_relay_url} && length $options{authority_relay_url}) {
  $authority_relay = {
    url => $options{authority_relay_url},
  };
  $authority_relay->{query_timeout_ms} = 0 + $options{authority_relay_query_timeout_ms}
    if defined $options{authority_relay_query_timeout_ms};
  $authority_relay->{poll_interval_ms} = 0 + $options{authority_relay_poll_interval_ms}
    if defined $options{authority_relay_poll_interval_ms};
}

_append_log($log_file, "starting IRC service\n");

my $adapter_lib = File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-adapter-irc', 'lib');
my $program_path = File::Spec->catfile($FindBin::Bin, 'overnet-irc-server.pl');
my $child_wrapper = q{$SIG{INT} = 'IGNORE'; exec $^X, @ARGV or die "exec failed: $!";};

my $runtime = Overnet::Program::Runtime->new(
  config => {
    adapter_id       => $options{adapter_id},
    network          => $options{network},
    listen_host      => $options{listen_host},
    listen_port      => 0 + $options{listen_port},
    server_name      => $options{server_name},
    signing_key_file => $signing_key_file,
    adapter_config   => $adapter_config,
    (defined $authority_relay ? (authority_relay => $authority_relay) : ()),
    (defined $tls_config ? (tls => $tls_config) : ()),
  },
);
die "Failed to register IRC adapter definition\n"
  unless $runtime->register_adapter_definition(
    adapter_id => $options{adapter_id},
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$adapter_lib],
      constructor_args => {},
    },
  );

my $host = Overnet::Program::Host->new(
  command     => [$^X, '-e', $child_wrapper, $program_path],
  runtime     => $runtime,
  program_id  => 'overnet.program.irc_server',
  permissions => [
    'adapters.use',
    'subscriptions.read',
    'events.append',
    'events.read',
    'nostr.read',
    'nostr.write',
    'overnet.emit_event',
    'overnet.emit_state',
    'overnet.emit_private_message',
    'overnet.emit_capabilities',
  ],
  services => {
    'adapters.open_session'            => {},
    'adapters.map_input'               => {},
    'adapters.derive'                  => {},
    'adapters.close_session'           => {},
    'events.append'                    => {},
    'events.read'                      => {},
    'nostr.publish_event'              => {},
    'nostr.query_events'               => {},
    'nostr.open_subscription'          => {},
    'nostr.read_subscription_snapshot' => {},
    'nostr.close_subscription'         => {},
    'subscriptions.open'               => {},
    'subscriptions.close'              => {},
    'overnet.emit_event'               => {},
    'overnet.emit_state'               => {},
    'overnet.emit_private_message'     => {},
    'overnet.emit_capabilities'        => {},
  },
  startup_timeout_ms  => 2_000,
  shutdown_timeout_ms => 2_000,
);

my $shutdown_requested = 0;
my $notification_cursor = 0;

local $SIG{INT} = sub { $shutdown_requested = 1; };
local $SIG{TERM} = sub { $shutdown_requested = 1; };

$host->start;
my $ready_details = _wait_for_ready_details($host)
  or die "Program did not publish ready health details\n";
_write_health_file($health_file, {
  status  => 'ready',
  details => $ready_details,
});
_append_log($log_file, sprintf(
  "ready listen=%s:%s server=%s network=%s\n",
  $ready_details->{listen_host} || '',
  $ready_details->{listen_port} || '',
  $ready_details->{server_name} || '',
  $ready_details->{network} || '',
));
_write_new_notifications($host, \$notification_cursor, $log_file);

while (!$shutdown_requested) {
  $host->pump(timeout_ms => 100);
  _write_new_notifications($host, \$notification_cursor, $log_file);

  if ($host->has_exited) {
    my $exit_code = defined $host->exit_code ? $host->exit_code : 'signal';
    my $stderr = $host->stderr_output;
    _write_health_file($health_file, {
      status  => 'failed',
      details => {
        exit_code => $exit_code,
      },
    });
    die "IRC server exited unexpectedly ($exit_code)\n$stderr";
  }
}

_write_health_file($health_file, {
  status  => 'stopping',
  details => $ready_details,
});
_append_log($log_file, "shutting down IRC service\n");

my $shutdown = eval {
  $host->request_shutdown(reason => 'service shutdown');
};
if (!$shutdown) {
  my $error = $@ || "unknown shutdown error\n";
  chomp $error;
  die "Failed to shut down cleanly: $error\n";
}

_write_new_notifications($host, \$notification_cursor, $log_file);
_write_health_file($health_file, {
  status  => 'stopped',
  details => $ready_details,
});
_append_log($log_file, "stopped IRC service\n");
exit 0;

sub _wait_for_ready_details {
  my ($host) = @_;

  my $ready = $host->pump_until(
    timeout_ms => 2_000,
    condition  => sub {
      my ($current_host) = @_;
      for my $notification (@{$current_host->observed_notifications}) {
        next unless ($notification->{method} || '') eq 'program.health';
        next unless ($notification->{params}{status} || '') eq 'ready';
        next unless ref($notification->{params}{details}) eq 'HASH';
        return 1 if defined $notification->{params}{details}{listen_port};
      }
      return 0;
    },
  );
  return undef unless $ready;

  for my $notification (@{$host->observed_notifications}) {
    next unless ($notification->{method} || '') eq 'program.health';
    next unless ($notification->{params}{status} || '') eq 'ready';
    next unless ref($notification->{params}{details}) eq 'HASH';
    return $notification->{params}{details};
  }

  return undef;
}

sub _write_new_notifications {
  my ($host, $cursor_ref, $log_file_path) = @_;
  my $notifications = $host->observed_notifications;

  while ($$cursor_ref < @{$notifications}) {
    my $notification = $notifications->[$$cursor_ref++];
    my $method = $notification->{method} || '';
    my $params = $notification->{params} || {};

    if ($method eq 'program.log') {
      my $level = $params->{level} || 'info';
      my $message = $params->{message} || '';
      _append_log($log_file_path, "[program.$level] $message\n");
      next;
    }

    next unless $method eq 'program.health';
    my $status = $params->{status} || 'unknown';
    my $message = $params->{message} || '';
    _append_log($log_file_path, "[program.health] $status" . (length($message) ? ": $message" : '') . "\n");
  }
}

sub _append_log {
  my ($path, $message) = @_;
  return 1 unless defined $path;
  return 1 unless length $path;

  my $dir = dirname($path);
  make_path($dir) unless -d $dir;

  open my $fh, '>>', $path
    or die "Can't open IRC service log file $path: $!";
  print {$fh} $message
    or die "Can't write IRC service log file $path: $!";
  close $fh
    or die "Can't close IRC service log file $path: $!";
  return 1;
}

sub _write_health_file {
  my ($path, $payload) = @_;
  return 1 unless defined $path;
  return 1 unless length $path;

  my $dir = dirname($path);
  make_path($dir) unless -d $dir;

  my $tmp_path = $path . '.tmp.' . $$;
  open my $fh, '>', $tmp_path
    or die "Can't open IRC service health temp file $tmp_path: $!";
  print {$fh} JSON::PP->new->utf8->canonical->encode($payload)
    or die "Can't write IRC service health temp file $tmp_path: $!";
  close $fh
    or die "Can't close IRC service health temp file $tmp_path: $!";
  rename $tmp_path, $path
    or die "Can't rename IRC service health temp file $tmp_path to $path: $!";
  return 1;
}

sub _ensure_signing_key {
  my ($path) = @_;
  return 1 if -f $path;

  my $dir = dirname($path);
  make_path($dir)
    unless -d $dir;

  my $key = Overnet::Core::Nostr->generate_key;
  $key->save_privkey($path);
  chmod 0600, $path;
  return 1;
}

sub _ensure_tls_material {
  my (%args) = @_;
  my $cert_chain_file = $args{cert_chain_file};
  my $private_key_file = $args{private_key_file};
  my $listen_host = $args{listen_host};

  return 1 if -f $cert_chain_file && -f $private_key_file;

  my $cert_dir = dirname($cert_chain_file);
  make_path($cert_dir)
    unless -d $cert_dir;
  my $key_dir = dirname($private_key_file);
  make_path($key_dir)
    unless -d $key_dir;

  my @subject_alt_names = (
    [ DNS => 'localhost' ],
    [ IP  => '127.0.0.1' ],
  );
  if (defined $listen_host && length $listen_host && $listen_host ne 'localhost' && $listen_host ne '127.0.0.1') {
    if ($listen_host =~ /\A\d{1,3}(?:\.\d{1,3}){3}\z/) {
      push @subject_alt_names, [ IP => $listen_host ];
    } else {
      push @subject_alt_names, [ DNS => $listen_host ];
    }
  }

  my ($cert, $key) = CERT_create(
    subject => {
      commonName => (
        defined $listen_host && length($listen_host)
          ? $listen_host
          : 'localhost'
      ),
    },
    subjectAltNames => \@subject_alt_names,
  );
  PEM_cert2file($cert, $cert_chain_file);
  PEM_key2file($key, $private_key_file);
  chmod 0600, $private_key_file;
  return 1;
}

sub _default_state_dir {
  my $xdg = $ENV{XDG_STATE_HOME};
  if (defined $xdg && !ref($xdg) && length($xdg)) {
    return File::Spec->catdir($xdg, 'overnet-program-irc');
  }
  return File::Spec->catdir($ENV{HOME} || '.', '.local', 'state', 'overnet-program-irc');
}

sub _usage {
  return <<'USAGE';
Usage: overnet-irc-service.pl [options]

  --adapter-id ID
  --network NAME
  --listen-host HOST
  --listen-port PORT
  --server-name NAME
  --signing-key-file PATH
  --group-host HOST
  --channel-group CHANNEL=GROUP_ID
  --authority-relay-url URL
  --authority-relay-query-timeout-ms N
  --authority-relay-poll-interval-ms N
  --tls
  --tls-cert-chain-file PATH
  --tls-private-key-file PATH
  --tls-ca-file PATH
  --tls-min-version VERSION
  --tls-verify-peer
  --health-file PATH
  --log-file PATH
  --help
USAGE
}
