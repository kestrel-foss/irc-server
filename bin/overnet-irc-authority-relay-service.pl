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
use IPC::Open3 qw(open3);
use Net::Nostr::Client;
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Time::HiRes qw(sleep time);

my %options = (
  host       => '127.0.0.1',
  port       => 7448,
  grant_kind => 14142,
);
my $health_file;
my $log_file;
my $help = 0;

GetOptions(
  'host=s'       => \$options{host},
  'port=i'       => \$options{port},
  'relay-url=s'  => \$options{relay_url},
  'grant-kind=i' => \$options{grant_kind},
  'store-file=s' => \$options{store_file},
  'health-file=s' => \$health_file,
  'log-file=s'    => \$log_file,
  'help'          => \$help,
) or die _usage();

if ($help) {
  print _usage();
  exit 0;
}

die "--host is required\n"
  unless defined $options{host} && !ref($options{host}) && length($options{host});
die "--port must be a non-negative integer\n"
  unless defined $options{port} && !ref($options{port}) && $options{port} =~ /\A\d+\z/;
die "--grant-kind must be a positive integer\n"
  unless defined $options{grant_kind}
    && !ref($options{grant_kind})
    && $options{grant_kind} =~ /\A[1-9]\d*\z/;
die "--store-file must be a non-empty string\n"
  if defined $options{store_file} && (ref($options{store_file}) || $options{store_file} eq '');

$options{relay_url} ||= sprintf('ws://%s:%d', $options{host}, $options{port});
$options{store_file} ||= File::Spec->catfile(_default_state_dir(), 'authority-relay-store.json');

_append_log($log_file, "starting authoritative IRC relay service\n");

my $program_path = File::Spec->catfile($FindBin::Bin, 'overnet-irc-authority-relay.pl');
my $child = _spawn_child(
  $^X,
  $program_path,
  '--host', $options{host},
  '--port', $options{port},
  '--relay-url', $options{relay_url},
  '--grant-kind', $options{grant_kind},
  '--store-file', $options{store_file},
);

eval {
  _wait_for_relay_ready($options{relay_url});
  _write_health_file($health_file, {
    status  => 'ready',
    details => {
      listen_host => $options{host},
      listen_port => 0 + $options{port},
      relay_url   => $options{relay_url},
      grant_kind  => 0 + $options{grant_kind},
      store_file  => $options{store_file},
    },
  });
  _append_log($log_file, sprintf(
    "ready relay=%s listen=%s:%s\n",
    $options{relay_url},
    $options{host},
    $options{port},
  ));
};
if ($@) {
  my $error = $@;
  _stop_child($child);
  die $error;
}

my $shutdown_requested = 0;
local $SIG{INT} = sub { $shutdown_requested = 1; };
local $SIG{TERM} = sub { $shutdown_requested = 1; };

while (!$shutdown_requested) {
  my $reaped = waitpid($child->{pid}, WNOHANG);
  if ($reaped == $child->{pid}) {
    my $exit_code = $? >> 8;
    _write_health_file($health_file, {
      status  => 'failed',
      details => {
        exit_code => $exit_code,
        relay_url => $options{relay_url},
      },
    });
    die "authoritative IRC relay exited unexpectedly ($exit_code)\n";
  }
  sleep 0.1;
}

_write_health_file($health_file, {
  status  => 'stopping',
  details => {
    listen_host => $options{host},
    listen_port => 0 + $options{port},
    relay_url   => $options{relay_url},
  },
});
_append_log($log_file, "shutting down authoritative IRC relay service\n");
_stop_child($child);
_write_health_file($health_file, {
  status  => 'stopped',
  details => {
    listen_host => $options{host},
    listen_port => 0 + $options{port},
    relay_url   => $options{relay_url},
  },
});
_append_log($log_file, "stopped authoritative IRC relay service\n");
exit 0;

sub _spawn_child {
  my (@command) = @_;
  my $stderr = gensym();
  my $pid = open3(
    my $stdin,
    my $stdout,
    $stderr,
    @command,
  );
  close $stdin;
  return {
    pid    => $pid,
    stdout => $stdout,
    stderr => $stderr,
  };
}

sub _stop_child {
  my ($child) = @_;
  return unless $child && $child->{pid};

  kill 'TERM', $child->{pid};
  my $deadline = time() + 5;
  while (time() < $deadline) {
    my $reaped = waitpid($child->{pid}, WNOHANG);
    last if $reaped == $child->{pid};
    sleep 0.05;
  }

  if (waitpid($child->{pid}, WNOHANG) == 0) {
    kill 'KILL', $child->{pid};
    waitpid($child->{pid}, 0);
  }

  close $child->{stdout} if $child->{stdout};
  close $child->{stderr} if $child->{stderr};
}

sub _wait_for_relay_ready {
  my ($relay_url) = @_;
  my $deadline = time() + 5;

  while (time() < $deadline) {
    my $ok = eval {
      my $client = Net::Nostr::Client->new;
      $client->connect($relay_url);
      $client->disconnect;
      1;
    };
    return 1 if $ok;
    sleep 0.05;
  }

  die "authoritative IRC relay did not become ready at $relay_url\n";
}

sub _append_log {
  my ($path, $message) = @_;
  return 1 unless defined $path;
  return 1 unless length $path;

  my $dir = dirname($path);
  make_path($dir) unless -d $dir;

  open my $fh, '>>', $path
    or die "Can't open authoritative relay log file $path: $!";
  print {$fh} $message
    or die "Can't write authoritative relay log file $path: $!";
  close $fh
    or die "Can't close authoritative relay log file $path: $!";
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
    or die "Can't open authoritative relay health temp file $tmp_path: $!";
  print {$fh} JSON::PP->new->utf8->canonical->encode($payload)
    or die "Can't write authoritative relay health temp file $tmp_path: $!";
  close $fh
    or die "Can't close authoritative relay health temp file $tmp_path: $!";
  rename $tmp_path, $path
    or die "Can't rename authoritative relay health temp file $tmp_path to $path: $!";
  return 1;
}

sub _default_state_dir {
  my $xdg = $ENV{XDG_STATE_HOME};
  if (defined $xdg && !ref($xdg) && length($xdg)) {
    return File::Spec->catdir($xdg, 'irc-server');
  }
  return File::Spec->catdir($ENV{HOME} || '.', '.local', 'state', 'irc-server');
}

sub _usage {
  return <<'USAGE';
Usage: overnet-irc-authority-relay-service.pl [options]

  --host HOST
  --port PORT
  --relay-url URL
  --grant-kind KIND
  --store-file PATH
  --health-file PATH
  --log-file PATH
  --help
USAGE
}
