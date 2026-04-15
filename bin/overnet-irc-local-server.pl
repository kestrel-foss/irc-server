use strict;
use warnings;
use Cwd qw(abs_path);
use File::Basename qw(dirname);
use File::Path qw(make_path);
use File::Spec;
use FindBin;
use Getopt::Long qw(GetOptions);
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../../overnet-code/lib";
use lib "$FindBin::Bin/../../overnet-code/local/lib/perl5";
use IO::Socket::SSL::Utils qw(CERT_create PEM_cert2file PEM_key2file);

use Overnet::Core::Nostr;
use Overnet::Program::Host;
use Overnet::Program::Runtime;

my %options = (
  adapter_id   => 'irc.local',
  network      => 'local',
  listen_host  => '127.0.0.1',
  listen_port  => 16667,
  server_name  => 'overnet.irc.local',
  tls          => 0,
  tls_min_version => 'TLSv1.2',
);
my $help = 0;

GetOptions(
  'adapter-id=s'       => \$options{adapter_id},
  'network=s'          => \$options{network},
  'listen-host=s'      => \$options{listen_host},
  'listen-port=i'      => \$options{listen_port},
  'server-name=s'      => \$options{server_name},
  'signing-key-file=s' => \$options{signing_key_file},
  'tls!'               => \$options{tls},
  'tls-cert-chain-file=s' => \$options{tls_cert_chain_file},
  'tls-private-key-file=s' => \$options{tls_private_key_file},
  'tls-ca-file=s'      => \$options{tls_ca_file},
  'tls-min-version=s'  => \$options{tls_min_version},
  'tls-verify-peer!'   => \$options{tls_verify_peer},
  'help'               => \$help,
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
  : File::Spec->catfile(_default_state_dir(), 'local-demo-signing-key.pem');
_ensure_signing_key($signing_key_file);

my $tls_config;
if ($options{tls}) {
  my $tls_cert_chain_file = defined $options{tls_cert_chain_file} && length $options{tls_cert_chain_file}
    ? $options{tls_cert_chain_file}
    : File::Spec->catfile(_default_state_dir(), 'local-demo-tls-cert.pem');
  my $tls_private_key_file = defined $options{tls_private_key_file} && length $options{tls_private_key_file}
    ? $options{tls_private_key_file}
    : File::Spec->catfile(_default_state_dir(), 'local-demo-tls-key.pem');

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
    adapter_config   => {},
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
    'overnet.emit_event',
    'overnet.emit_state',
    'overnet.emit_private_message',
    'overnet.emit_capabilities',
  ],
  services => {
    'adapters.open_session'      => {},
    'adapters.map_input'         => {},
    'adapters.close_session'     => {},
    'subscriptions.open'         => {},
    'subscriptions.close'        => {},
    'overnet.emit_event'         => {},
    'overnet.emit_state'         => {},
    'overnet.emit_private_message' => {},
    'overnet.emit_capabilities'  => {},
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
_print_new_notifications($host, \$notification_cursor);

my $client_script = abs_path(File::Spec->catfile($FindBin::Bin, 'overnet-irc-chat-client.pl'))
  || File::Spec->catfile($FindBin::Bin, 'overnet-irc-chat-client.pl');

print "Overnet IRC local demo server is ready.\n";
print "Listening on $ready_details->{listen_host}:$ready_details->{listen_port}\n";
print "Network: $ready_details->{network}\n";
print "Server name: $ready_details->{server_name}\n";
print "Signing key: $signing_key_file\n";
if (defined $tls_config) {
  print "TLS: enabled\n";
  print "TLS cert: $tls_config->{cert_chain_file}\n";
  print "TLS key: $tls_config->{private_key_file}\n";
  print "TLS min version: $tls_config->{min_version}\n";
}
print "\n";
print "Open two more terminals and run:\n";
print "  /opt/perl-5.42/bin/perl $client_script --nick alice --port $ready_details->{listen_port}" . (defined $tls_config ? ' --tls --tls-no-verify' : '') . "\n";
print "  /opt/perl-5.42/bin/perl $client_script --nick bob --port $ready_details->{listen_port}" . (defined $tls_config ? ' --tls --tls-no-verify' : '') . "\n";
print "\n";
print "The client auto-joins #overnet. Plain text sends to the current target.\n";
if (defined $tls_config) {
  my $hexchat_host = _hexchat_connect_host($ready_details->{listen_host});
  my $hexchat_uri = sprintf('ircs://%s:%d/%%23overnet', $hexchat_host, $ready_details->{listen_port});
  print "HexChat can connect without -insecure.\n";
  print "For the local generated cert, run:\n";
  print "  SSL_CERT_FILE=" . _shell_quote($tls_config->{cert_chain_file}) . " hexchat " . _shell_quote($hexchat_uri) . "\n";
  print "If you supply your own CA-trusted cert/key, normal HexChat TLS works without SSL_CERT_FILE.\n";
}
print "Press Ctrl-C here to shut the server down.\n";

while (!$shutdown_requested) {
  $host->pump(timeout_ms => 100);
  _print_new_notifications($host, \$notification_cursor);

  if ($host->has_exited) {
    my $exit_code = defined $host->exit_code ? $host->exit_code : 'signal';
    my $stderr = $host->stderr_output;
    die "IRC server exited unexpectedly ($exit_code)\n$stderr";
  }
}

print "\nShutting down local demo server...\n";
_print_new_notifications($host, \$notification_cursor);

my $shutdown = eval {
  $host->request_shutdown(reason => 'local demo shutdown');
};
if (!$shutdown) {
  my $error = $@ || "unknown shutdown error\n";
  chomp $error;
  die "Failed to shut down cleanly: $error\n";
}

_print_new_notifications($host, \$notification_cursor);
print "Server stopped.\n";
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

sub _print_new_notifications {
  my ($host, $cursor_ref) = @_;
  my $notifications = $host->observed_notifications;

  while ($$cursor_ref < @{$notifications}) {
    my $notification = $notifications->[$$cursor_ref++];
    my $method = $notification->{method} || '';
    my $params = $notification->{params} || {};

    if ($method eq 'program.log') {
      my $level = $params->{level} || 'info';
      my $message = $params->{message} || '';
      print STDERR "[program.$level] $message\n";
      next;
    }

    next unless $method eq 'program.health';
    next if ($params->{status} || '') eq 'ready';

    my $status = $params->{status} || 'unknown';
    my $message = $params->{message} || '';
    print STDERR "[program.health] $status";
    print STDERR ": $message" if length $message;
    print STDERR "\n";
  }
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
  return File::Spec->catdir($ENV{XDG_STATE_HOME}, 'overnet-program-irc')
    if defined $ENV{XDG_STATE_HOME} && length $ENV{XDG_STATE_HOME};
  return File::Spec->catdir($ENV{HOME}, '.local', 'state', 'overnet-program-irc')
    if defined $ENV{HOME} && length $ENV{HOME};
  return File::Spec->catdir(File::Spec->tmpdir, 'overnet-program-irc');
}

sub _hexchat_connect_host {
  my ($listen_host) = @_;
  return '127.0.0.1'
    if !defined $listen_host || !length $listen_host || $listen_host eq '0.0.0.0' || $listen_host eq '::';
  return $listen_host;
}

sub _shell_quote {
  my ($value) = @_;
  $value = '' unless defined $value;
  $value =~ s/'/'"'"'/g;
  return "'$value'";
}

sub _usage {
  return <<'USAGE';
Usage:
  /opt/perl-5.42/bin/perl overnet-program-irc/bin/overnet-irc-local-server.pl [options]

Options:
  --adapter-id ID         Adapter id to register and use (default: irc.local)
  --network NAME          IRC network name for adapted object ids (default: local)
  --listen-host HOST      Listen host for the local IRC server (default: 127.0.0.1)
  --listen-port PORT      Listen port for the local IRC server (default: 16667)
  --server-name NAME      IRC server name shown to clients (default: overnet.irc.local)
  --signing-key-file PATH Reuse this signing key instead of auto-creating one
  --tls                   Enable TLS on the local IRC listener
  --tls-cert-chain-file PATH
                          TLS certificate chain file (auto-generated for local demo if omitted)
  --tls-private-key-file PATH
                          TLS private key file (auto-generated for local demo if omitted)
  --tls-ca-file PATH      Optional CA file to require verified client certificates
  --tls-min-version NAME  TLS minimum version (default: TLSv1.2)
  --tls-verify-peer       Require peer certificate verification
  --help                  Show this message
USAGE
}
