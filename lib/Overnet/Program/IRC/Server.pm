package Overnet::Program::IRC::Server;

use strict;
use warnings;
use IO::Handle;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL ();
use JSON::PP ();
use Net::Nostr::Event;
use Net::Nostr::Key;
use Time::HiRes qw(time);
use Overnet::Program::Protocol;
use Overnet::Program::TLSConfig;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;

  my $protocol = $args{protocol} || Overnet::Program::Protocol->new;
  my $program_id = $args{program_id} || 'overnet.program.irc_server';
  my $program_version = exists $args{program_version} ? $args{program_version} : $VERSION;
  my $supported_protocol_versions = $args{supported_protocol_versions} || ['0.1'];

  die "protocol must be an Overnet::Program::Protocol instance\n"
    unless ref($protocol) && $protocol->isa('Overnet::Program::Protocol');
  die "program_id is required\n"
    unless defined $program_id && !ref($program_id) && length($program_id);
  die "program_version must be a non-empty string\n"
    if defined $program_version && (ref($program_version) || !length($program_version));
  die "supported_protocol_versions must be a non-empty array of strings\n"
    unless ref($supported_protocol_versions) eq 'ARRAY'
      && @{$supported_protocol_versions}
      && !grep { !defined($_) || ref($_) || !length($_) } @{$supported_protocol_versions};

  return bless {
    protocol                    => $protocol,
    program_id                  => $program_id,
    program_version             => $program_version,
    supported_protocol_versions => [ @{$supported_protocol_versions} ],
    next_request_id             => 1,
    pending_messages            => [],
    next_client_id              => 1,
    clients                     => {},
    channels                    => {},
    nick_to_client_id           => {},
    suppress_subscription_event_ids => {},
    inputs_processed            => 0,
    events_emitted              => 0,
    state_emitted               => 0,
    capabilities_emitted        => 0,
  }, $class;
}

sub run {
  my ($self) = @_;

  binmode(STDIN, ':raw');
  binmode(STDOUT, ':raw');
  binmode(STDERR, ':raw');
  STDOUT->autoflush(1);
  STDERR->autoflush(1);

  $self->_send_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => $self->{program_id},
      supported_protocol_versions => $self->{supported_protocol_versions},
      (defined $self->{program_version}
        ? (program_version => $self->{program_version})
        : ()),
    )
  );

  while (!$self->{initialized} && !$self->{shutdown_complete}) {
    my $message = $self->_next_runtime_message;

    if (($message->{type} || '') eq 'request' && ($message->{method} || '') eq 'runtime.init') {
      $self->_handle_runtime_init($message);
      next;
    }

    if (($message->{type} || '') eq 'request' && ($message->{method} || '') eq 'runtime.shutdown') {
      $self->_handle_runtime_shutdown($message);
      next;
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.fatal') {
      die "runtime fatal: " . ($message->{params}{code} || 'unknown') . "\n";
    }

    die "Unexpected message before runtime.init\n";
  }

  return 1 if $self->{shutdown_complete};

  $self->_run_server_loop;
  return 1;
}

sub _handle_runtime_init {
  my ($self, $message) = @_;
  my $params = $message->{params} || {};

  my $loaded = eval {
    $self->_load_runtime_init($params);
    $self->_open_listen_socket;
    1;
  };
  if (!$loaded) {
    my $error = $@ || "Invalid runtime.init configuration\n";
    chomp $error;
    $self->_send_message(
      Overnet::Program::Protocol::build_response_error(
        id      => $message->{id},
        code    => 'program.operation_failed',
        message => $error,
      )
    );
    $self->_close_all_clients;
    $self->_close_listen_socket;
    return;
  }

  $self->_send_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $message->{id},
    )
  );

  $self->_send_message(Overnet::Program::Protocol::build_program_ready());

  my $opened = eval {
    $self->_open_adapter_session;
    1;
  };
  if (!$opened) {
    my $error = $@ || "Failed to open IRC adapter session\n";
    chomp $error;
    return if $error eq '__shutdown__';
    $self->_health(
      status  => 'failed',
      message => $error,
    );
    die "$error\n";
  }

  $self->_log(
    level   => 'info',
    message => 'runtime.init accepted',
    context => {
      instance_id => $self->{instance_id},
      adapter_id  => $self->{config}{adapter_id},
      network     => $self->{config}{network},
      listen_host => $self->{config}{listen_host},
      listen_port => $self->{config}{listen_port},
      server_name => $self->{config}{server_name},
    },
  );
  $self->_health(
    status  => 'ready',
    message => 'IRC server listening',
    details => {
      network           => $self->{config}{network},
      listen_host       => $self->{config}{listen_host},
      listen_port       => $self->{config}{listen_port},
      server_name       => $self->{config}{server_name},
      clients_connected => 0,
      joined_channels   => [],
      inputs_processed  => 0,
      events_emitted    => 0,
      state_emitted     => 0,
    },
  );
  $self->{initialized} = 1;
}

sub _handle_runtime_shutdown {
  my ($self, $message) = @_;
  $self->_send_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $message->{id},
    )
  );
  $self->{shutdown_complete} = 1;
}

sub _load_runtime_init {
  my ($self, $params) = @_;

  die "runtime.init params.instance_id is required\n"
    unless defined $params->{instance_id} && !ref($params->{instance_id}) && length($params->{instance_id});
  die "runtime.init params.config must be an object\n"
    unless ref($params->{config}) eq 'HASH';

  my $config = $params->{config};
  my $adapter_id = $config->{adapter_id};
  my $network = $config->{network};
  my $listen_host = exists $config->{listen_host} ? $config->{listen_host} : '127.0.0.1';
  my $listen_port = exists $config->{listen_port} ? $config->{listen_port} : 6667;
  my $listen_backlog = exists $config->{listen_backlog} ? $config->{listen_backlog} : 10;
  my $server_name = exists $config->{server_name} ? $config->{server_name} : 'overnet.irc.local';
  my $signing_key_file = $config->{signing_key_file};
  my $adapter_config = exists $config->{adapter_config} ? $config->{adapter_config} : {};
  my $tls = exists $config->{tls}
    ? Overnet::Program::TLSConfig->normalize(
        tls           => $config->{tls},
        implicit_mode => 'server',
      )
    : undef;

  die "config.adapter_id is required\n"
    unless defined $adapter_id && !ref($adapter_id) && length($adapter_id);
  die "config.network is required\n"
    unless defined $network && !ref($network) && length($network);
  die "config.listen_host is required\n"
    unless defined $listen_host && !ref($listen_host) && length($listen_host);
  die "config.listen_port must be an integer between 0 and 65535\n"
    unless defined $listen_port && !ref($listen_port) && $listen_port =~ /\A(?:0|[1-9]\d{0,4})\z/ && $listen_port <= 65535;
  die "config.listen_backlog must be a positive integer\n"
    unless defined $listen_backlog && !ref($listen_backlog) && $listen_backlog =~ /\A[1-9]\d*\z/;
  die "config.server_name is required\n"
    unless defined $server_name && !ref($server_name) && length($server_name);
  die "config.signing_key_file is required\n"
    unless defined $signing_key_file && !ref($signing_key_file) && length($signing_key_file);
  die "config.adapter_config must be an object\n"
    unless ref($adapter_config) eq 'HASH';

  my $signing_key = Net::Nostr::Key->new(privkey => $signing_key_file);

  $self->{instance_id} = $params->{instance_id};
  $self->{config} = {
    adapter_id       => $adapter_id,
    network          => $network,
    listen_host      => $listen_host,
    listen_port      => 0 + $listen_port,
    listen_backlog   => 0 + $listen_backlog,
    server_name      => $server_name,
    signing_key_file => $signing_key_file,
    adapter_config   => { %{$adapter_config} },
    (defined $tls ? (tls => $tls) : ()),
  };
  $self->{signing_key} = $signing_key;
  $self->{tls_server_args} = defined $tls
    ? Overnet::Program::TLSConfig->server_start_args($tls)
    : undef;

  return 1;
}

sub _open_listen_socket {
  my ($self) = @_;

  my $listener = IO::Socket::INET->new(
    LocalAddr => $self->{config}{listen_host},
    LocalPort => $self->{config}{listen_port},
    Listen    => $self->{config}{listen_backlog},
    Proto     => 'tcp',
    ReuseAddr => 1,
  ) or die "Failed to listen on $self->{config}{listen_host}:$self->{config}{listen_port}: $!\n";

  binmode($listener, ':raw');
  $listener->autoflush(1);

  $self->{listener_socket} = $listener;
  $self->{config}{listen_port} = $listener->sockport;
  return 1;
}

sub _open_adapter_session {
  my ($self) = @_;

  my $open = $self->_request(
    method => 'adapters.open_session',
    params => {
      adapter_id => $self->{config}{adapter_id},
      config     => $self->{config}{adapter_config},
    },
  );
  $self->{adapter_session_id} = $open->{adapter_session_id};
  return $self->{adapter_session_id};
}

sub _run_server_loop {
  my ($self) = @_;

  while (!$self->{shutdown_complete}) {
    my $drained = $self->_drain_pending_runtime_messages;
    last if $self->{shutdown_complete};
    next if $drained;

    my @handles = (\*STDIN);
    push @handles, $self->{listener_socket}
      if defined $self->{listener_socket};
    push @handles, map { $self->{clients}{$_}{socket} }
      sort keys %{$self->{clients}};

    my $selector = IO::Select->new(@handles);
    my @ready = $selector->can_read(0.1);
    next unless @ready;

    for my $handle (@ready) {
      if ($self->_is_listener_socket($handle)) {
        $self->_accept_client;
        next;
      }

      if ($self->_is_runtime_stdin($handle)) {
        $self->_read_runtime_chunk;
        $self->_drain_pending_runtime_messages;
        last if $self->{shutdown_complete};
        next;
      }

      my $client_id = $self->_client_id_for_handle($handle);
      next unless defined $client_id;
      $self->_pump_client_socket($client_id);
      last if $self->{shutdown_complete};
    }
  }

  $self->_close_all_clients;
  $self->_close_listen_socket;
  return 1;
}

sub _accept_client {
  my ($self) = @_;
  return 1 unless defined $self->{listener_socket};

  my $socket = $self->{listener_socket}->accept
    or die "Failed to accept IRC client connection: $!\n";

  binmode($socket, ':raw');
  $socket->autoflush(1);

  if (defined $self->{tls_server_args}) {
    my $upgraded = eval {
      IO::Socket::SSL->start_SSL(
        $socket,
        %{$self->{tls_server_args}},
      ) or die(IO::Socket::SSL::errstr() || "unknown TLS handshake failure");
    };
    if (!$upgraded) {
      my $error = $@ || "unknown TLS handshake failure";
      chomp $error;
      $self->_log(
        level   => 'warn',
        message => 'TLS handshake failed for IRC client connection',
        context => {
          error => $error,
        },
      );
      close $socket;
      return 1;
    }
    $socket = $upgraded;
  }

  my $client_id = 'client-' . $self->{next_client_id}++;
  $self->{clients}{$client_id} = {
    id              => $client_id,
    socket          => $socket,
    read_buffer     => '',
    registered      => 0,
    nick            => undef,
    username        => undef,
    realname        => undef,
    joined_channels => {},
    peerhost        => eval { $socket->peerhost } || '',
    peerport        => eval { $socket->peerport } || 0,
  };

  return 1;
}

sub _pump_client_socket {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;

  my $bytes = sysread($client->{socket}, my $chunk, 4096);
  if (!defined $bytes) {
    die "Failed to read IRC client socket: $!\n"
      unless $!{EINTR};
    return 1;
  }

  if ($bytes == 0) {
    $self->_disconnect_client(
      $client_id,
      emit_quit => 0,
      reason    => 'client disconnected',
    );
    return 1;
  }

  $client->{read_buffer} .= $chunk;
  while ($client->{read_buffer} =~ s/\A([^\n]*\n)//) {
    my $line = $1;
    $line =~ s/\r?\n\z//;
    next unless length $line;
    $self->_handle_client_line($client_id, $line);
    last unless exists $self->{clients}{$client_id};
    last if $self->{shutdown_complete};
  }

  return 1;
}

sub _handle_client_line {
  my ($self, $client_id, $line) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;
  my $message = $self->_parse_irc_message($line);
  return 1 unless $message;

  my $command = $message->{command};
  my @params = @{$message->{params} || []};

  if ($command eq 'NICK') {
    return 1 unless @params >= 1 && defined $params[0] && length $params[0];
    my $requested_nick = $params[0];

    if ($client->{registered}) {
      my $old_nick = $client->{nick};
      my $new_nick = $requested_nick;
      return 1 if defined $old_nick && $old_nick eq $new_nick;
      if ($self->_nick_in_use($new_nick, exclude_client_id => $client_id)) {
        $self->_send_nick_in_use($client_id, $new_nick);
        return 1;
      }

      my @shared_client_ids = $self->_shared_client_ids_for_client($client_id);
      $self->_send_line_to_client_ids(
        \@shared_client_ids,
        sprintf(':%s NICK :%s', $old_nick, $new_nick),
      );
      $self->_rename_client_channels(
        $client,
        old_nick => $old_nick,
        new_nick => $new_nick,
      );
      $self->_assign_client_nick($client_id, $new_nick);
      $self->_emit_client_input(
        $client,
        {
          command  => 'NICK',
          nick     => $old_nick,
          new_nick => $new_nick,
        },
        suppress_render_event_types => {
          'irc.nick' => 1,
        },
      ) if defined $old_nick && length $old_nick;
      return 1;
    }

    return 1 if defined $client->{nick} && $client->{nick} eq $requested_nick;
    if ($self->_nick_in_use($requested_nick, exclude_client_id => $client_id)) {
      $self->_send_nick_in_use($client_id, $requested_nick);
      return 1;
    }

    $self->_assign_client_nick($client_id, $requested_nick);
    $self->_register_client_if_ready($client);
    return 1;
  }

  if ($command eq 'USER') {
    return 1 if $client->{registered};
    return 1 unless @params >= 4;

    $client->{username} = $params[0];
    $client->{realname} = $params[3];
    $self->_register_client_if_ready($client);
    return 1;
  }

  if (!$client->{registered}) {
    return 1;
  }

  if ($command eq 'PING') {
    my $token = defined $params[0] ? $params[0] : '';
    $self->_send_client_line($client_id, 'PONG :' . $token);
    return 1;
  }

  if ($command eq 'JOIN') {
    return 1 unless @params >= 1;
    my $channel = $params[0];
    return 1 unless $self->_is_channel_name($channel);
    return 1 if $client->{joined_channels}{$channel};

    $self->_add_client_to_channel($client_id, $channel);
    $self->_ensure_channel_subscription($channel);
    $self->_broadcast_channel_line(
      $channel,
      sprintf(':%s JOIN %s', $client->{nick}, $channel),
    );
    $self->_send_join_bootstrap($client_id, $channel);
    $self->_emit_client_input(
      $client,
      {
        command => 'JOIN',
        target  => $channel,
      },
      suppress_render_event_types => {
        'chat.join' => 1,
      },
    );
    return 1;
  }

  if ($command eq 'PART') {
    return 1 unless @params >= 1;
    my $channel = $params[0];
    return 1 unless $client->{joined_channels}{$channel};

    my $reason = @params >= 2 ? $params[1] : undef;
    my $line = sprintf(':%s PART %s', $client->{nick}, $channel);
    $line .= ' :' . $reason
      if defined $reason && length $reason;
    $self->_broadcast_channel_line($channel, $line);
    $self->_remove_client_from_channel($client_id, $channel);
    $self->_emit_client_input(
      $client,
      {
        command => 'PART',
        target  => $channel,
        (defined $reason ? (text => $reason) : ()),
      },
      suppress_render_event_types => {
        'chat.part' => 1,
      },
    );
    return 1;
  }

  if ($command eq 'PRIVMSG' || $command eq 'NOTICE' || $command eq 'TOPIC') {
    return 1 unless @params >= 2;
    my $target = $params[0];
    return 1 unless $self->_is_channel_name($target);
    return 1 unless $client->{joined_channels}{$target};

    $self->_emit_client_input(
      $client,
      {
        command => $command,
        target  => $target,
        text    => $params[1],
      },
    );
    return 1;
  }

  if ($command eq 'QUIT') {
    my $reason = @params >= 1 ? $params[0] : undef;
    $self->_disconnect_client(
      $client_id,
      emit_quit => 1,
      reason    => $reason,
    );
    return 1;
  }

  return 1;
}

sub _register_client_if_ready {
  my ($self, $client) = @_;
  return 0 if $client->{registered};
  return 0 unless defined $client->{nick} && length($client->{nick});
  return 0 unless defined $client->{username} && length($client->{username});

  $client->{registered} = 1;
  $self->_send_client_line(
    $client->{id},
    sprintf(
      ':%s 001 %s :Welcome to Overnet IRC',
      $self->{config}{server_name},
      $client->{nick},
    ),
  );
  return 1;
}

sub _nick_in_use {
  my ($self, $nick, %args) = @_;
  return 0 unless defined $nick && !ref($nick) && length($nick);

  my $owner = $self->{nick_to_client_id}{$nick};
  return 0 unless defined $owner;
  return 0 if defined $args{exclude_client_id} && $owner eq $args{exclude_client_id};
  return 1;
}

sub _assign_client_nick {
  my ($self, $client_id, $nick) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  if (defined $client->{nick} && length($client->{nick}) && $client->{nick} ne $nick) {
    $self->_release_client_nick(
      $client_id,
      nick => $client->{nick},
    );
  }

  $client->{nick} = $nick;
  $self->{nick_to_client_id}{$nick} = $client_id;
  return 1;
}

sub _release_client_nick {
  my ($self, $client_id, %args) = @_;
  my $nick = defined $args{nick}
    ? $args{nick}
    : (
      exists $self->{clients}{$client_id}
        ? $self->{clients}{$client_id}{nick}
        : undef
    );
  return 0 unless defined $nick && !ref($nick) && length($nick);
  return 0 unless exists $self->{nick_to_client_id}{$nick};
  return 0 unless $self->{nick_to_client_id}{$nick} eq $client_id;

  delete $self->{nick_to_client_id}{$nick};
  return 1;
}

sub _send_nick_in_use {
  my ($self, $client_id, $attempted_nick) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $target = $client->{registered} && defined $client->{nick} && length($client->{nick})
    ? $client->{nick}
    : '*';
  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 433 %s %s :Nickname is already in use',
      $self->{config}{server_name},
      $target,
      $attempted_nick,
    ),
  );
  return 1;
}

sub _emit_client_input {
  my ($self, $client, $input, %opts) = @_;
  my %payload = (
    %{$input},
    network    => $self->{config}{network},
    nick       => $input->{nick} || $client->{nick},
    created_at => int(time()),
  );

  my $mapped = $self->_request(
    method => 'adapters.map_input',
    params => {
      adapter_session_id => $self->{adapter_session_id},
      input              => \%payload,
    },
  );
  $self->{inputs_processed}++;
  $self->_emit_mapped_result(
    $mapped,
    suppress_render_event_types => $opts{suppress_render_event_types},
  );

  return 1;
}

sub _ensure_channel_subscription {
  my ($self, $channel) = @_;
  my $state = $self->_channel_state($channel);
  return $state->{subscription_id}
    if defined $state->{subscription_id};

  my $subscription_id = 'channel:' . $self->_channel_object_id($channel);
  $self->_request(
    method => 'subscriptions.open',
    params => {
      subscription_id => $subscription_id,
      query           => {
        overnet_ot  => 'chat.channel',
        overnet_oid => $self->_channel_object_id($channel),
      },
    },
  );
  $state->{subscription_id} = $subscription_id;

  return $subscription_id;
}

sub _close_channel_subscription {
  my ($self, $channel) = @_;
  my $state = $self->{channels}{$channel}
    or return 1;
  return 1 unless defined $state->{subscription_id};

  my $subscription_id = delete $state->{subscription_id};
  $self->_request(
    method => 'subscriptions.close',
    params => {
      subscription_id => $subscription_id,
    },
  );

  return 1;
}

sub _add_client_to_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $state = $self->_channel_state($channel);
  $client->{joined_channels}{$channel} = 1;
  $state->{members}{$client_id} = 1;
  $self->_add_visible_nick($channel, $client->{nick});
  return 1;
}

sub _remove_client_from_channel {
  my ($self, $client_id, $channel, %opts) = @_;
  my $client = $self->{clients}{$client_id};
  my $state = $self->{channels}{$channel}
    or return 0;
  my $nick = defined $opts{nick}
    ? $opts{nick}
    : ($client ? $client->{nick} : undef);

  delete $client->{joined_channels}{$channel}
    if $client;
  delete $state->{members}{$client_id};
  $self->_remove_visible_nick($channel, $nick);

  if (!keys %{$state->{members}}) {
    $self->_close_channel_subscription($channel);
    delete $self->{channels}{$channel};
  }

  return 1;
}

sub _disconnect_client {
  my ($self, $client_id, %args) = @_;
  my $client = delete $self->{clients}{$client_id}
    or return 1;
  my $current_nick = $client->{nick};

  my @channels = sort keys %{$client->{joined_channels} || {}};
  if ($args{emit_quit}) {
    my $line = sprintf(':%s QUIT', $client->{nick});
    $line .= ' :' . $args{reason}
      if defined $args{reason} && length $args{reason};
    $self->_send_line_to_client_ids(
      [ $self->_shared_client_ids_for_channels(\@channels, exclude_client_id => $client_id) ],
      $line,
    );

    for my $channel (@channels) {
      $self->_remove_client_from_channel(
        $client_id,
        $channel,
        nick => $client->{nick},
      );
    }

    for my $channel (@channels) {
      $self->_emit_client_input(
        $client,
        {
          command => 'QUIT',
          target  => $channel,
          (defined $args{reason} ? (text => $args{reason}) : ()),
        },
        suppress_render_event_types => {
          'chat.quit' => 1,
        },
      );
    }
  } else {
    for my $channel (@channels) {
      $self->_remove_client_from_channel(
        $client_id,
        $channel,
        nick => $client->{nick},
      );
    }
  }

  $self->_release_client_nick(
    $client_id,
    nick => $current_nick,
  );

  close $client->{socket}
    if defined $client->{socket};

  return 1;
}

sub _handle_subscription_event {
  my ($self, $params) = @_;
  return 0 unless ref($params) eq 'HASH';
  return 0 unless ($params->{item_type} || '') eq 'event' || ($params->{item_type} || '') eq 'state';
  return 0 unless ref($params->{data}) eq 'HASH';

  my $data = $params->{data};
  if (defined $data->{id} && delete $self->{suppress_subscription_event_ids}{$data->{id}}) {
    return 0;
  }

  my $render = $self->_render_subscription_item(
    item_type => $params->{item_type},
    data      => $data,
  );
  return 0 unless $render;

  for my $client_id (@{$render->{client_ids}}) {
    $self->_send_client_line($client_id, $render->{line});
  }

  return scalar @{$render->{client_ids}};
}

sub _render_subscription_item {
  my ($self, %args) = @_;
  my $item_type = $args{item_type};
  my $data = $args{data};
  return undef unless ref($data) eq 'HASH';

  my $event = eval { Net::Nostr::Event->from_wire($data) };
  return undef unless $event;

  my %tags = $self->_first_tag_values($event->tags);
  my $content = eval { JSON::PP::decode_json($event->content) };
  return undef unless ref($content) eq 'HASH';
  my $provenance = $content->{provenance} || {};
  my $body = $content->{body} || {};
  my $event_type = $tags{overnet_et} || '';
  if (($tags{overnet_ot} || '') eq 'chat.channel') {
    my $channel = $self->_channel_name_from_object_id($tags{overnet_oid});
    return undef unless defined $channel;

    my $nick = $provenance->{external_identity};
    return undef unless defined $nick && !ref($nick) && length($nick);

    my $line;
    if ($item_type eq 'event' && $event_type eq 'chat.message') {
      return undef unless defined $body->{text} && !ref($body->{text});
      $line = sprintf(':%s PRIVMSG %s :%s', $nick, $channel, $body->{text});
    } elsif ($item_type eq 'event' && $event_type eq 'chat.notice') {
      return undef unless defined $body->{text} && !ref($body->{text});
      $line = sprintf(':%s NOTICE %s :%s', $nick, $channel, $body->{text});
    } elsif ($item_type eq 'state' && $event_type eq 'chat.topic') {
      return undef unless defined $body->{topic} && !ref($body->{topic});
      $line = sprintf(':%s TOPIC %s :%s', $nick, $channel, $body->{topic});
      $self->_channel_state($channel)->{topic_line} = $line;
    } elsif ($item_type eq 'event' && $event_type eq 'chat.join') {
      $self->_add_visible_nick($channel, $nick);
      $line = sprintf(':%s JOIN %s', $nick, $channel);
    } elsif ($item_type eq 'event' && $event_type eq 'chat.part') {
      $self->_remove_visible_nick($channel, $nick);
      $line = sprintf(':%s PART %s', $nick, $channel);
      $line .= ' :' . $body->{reason}
        if defined $body->{reason} && !ref($body->{reason}) && length($body->{reason});
    } elsif ($item_type eq 'event' && $event_type eq 'chat.quit') {
      $self->_remove_visible_nick($channel, $nick);
      $line = sprintf(':%s QUIT', $nick);
      $line .= ' :' . $body->{reason}
        if defined $body->{reason} && !ref($body->{reason}) && length($body->{reason});
    } else {
      return undef;
    }

    my @client_ids = grep {
      exists $self->{clients}{$_}
        && $self->{clients}{$_}{registered}
        && $self->{clients}{$_}{joined_channels}{$channel}
    } sort keys %{$self->{clients}};
    return undef unless @client_ids;

    return {
      channel    => $channel,
      line       => $line,
      client_ids => \@client_ids,
    };
  }

  if (($tags{overnet_ot} || '') eq 'irc.network' && $item_type eq 'event' && $event_type eq 'irc.nick') {
    my $network_object_id = 'irc:' . $self->{config}{network};
    return undef unless ($tags{overnet_oid} || '') eq $network_object_id;
    return undef unless defined $body->{old_nick} && !ref($body->{old_nick}) && length($body->{old_nick});
    return undef unless defined $body->{new_nick} && !ref($body->{new_nick}) && length($body->{new_nick});

    my @client_ids = $self->_shared_client_ids_for_nick($body->{old_nick});
    $self->_rename_visible_nick_everywhere(
      old_nick => $body->{old_nick},
      new_nick => $body->{new_nick},
    );
    return undef unless @client_ids;

    return {
      line       => sprintf(':%s NICK :%s', $body->{old_nick}, $body->{new_nick}),
      client_ids => \@client_ids,
    };
  }

  return undef;
}

sub _emit_mapped_result {
  my ($self, $result, %opts) = @_;
  my $suppress = $opts{suppress_render_event_types} || {};

  for my $event (@{$result->{events} || []}) {
    my $signed = $self->_sign_candidate_event($event);
    my %tags = $self->_first_tag_values($signed->{tags});
    if ($suppress->{$tags{overnet_et} || ''}) {
      $self->{suppress_subscription_event_ids}{$signed->{id}} = 1;
    }
    $self->_request(
      method => 'overnet.emit_event',
      params => { event => $signed },
    );
    $self->{events_emitted}++;
  }

  for my $state (@{$result->{state} || []}) {
    my $signed = $self->_sign_candidate_event($state);
    $self->_request(
      method => 'overnet.emit_state',
      params => { state => $signed },
    );
    $self->{state_emitted}++;
  }

  if (@{$result->{capabilities} || []}) {
    $self->_request(
      method => 'overnet.emit_capabilities',
      params => { capabilities => $result->{capabilities} },
    );
    $self->{capabilities_emitted} += scalar @{$result->{capabilities}};
  }

  return 1;
}

sub _sign_candidate_event {
  my ($self, $candidate) = @_;

  die "candidate event must be an object\n"
    unless ref($candidate) eq 'HASH';
  die "candidate event kind is required\n"
    unless defined $candidate->{kind} && !ref($candidate->{kind});
  die "candidate event created_at is required\n"
    unless defined $candidate->{created_at} && !ref($candidate->{created_at});
  die "candidate event tags must be an array\n"
    unless ref($candidate->{tags}) eq 'ARRAY';
  die "candidate event content is required\n"
    unless defined $candidate->{content} && !ref($candidate->{content});

  my $event = $self->{signing_key}->create_event(
    kind       => $candidate->{kind},
    created_at => $candidate->{created_at},
    tags       => $candidate->{tags},
    content    => $candidate->{content},
  );

  return $event->to_hash;
}

sub _request {
  my ($self, %args) = @_;
  my $method = $args{method};
  my $params = $args{params} || {};

  die "method is required\n"
    unless defined $method && !ref($method) && length($method);
  die "params must be an object\n"
    unless ref($params) eq 'HASH';

  my $id = 'program-' . $self->{next_request_id}++;
  $self->_send_message(
    Overnet::Program::Protocol::build_request(
      id     => $id,
      method => $method,
      params => $params,
    )
  );

  while (1) {
    my $message = @{$self->{pending_messages}}
      ? shift @{$self->{pending_messages}}
      : $self->_next_runtime_message;

    if (($message->{type} || '') eq 'response') {
      die "Unexpected response id while awaiting $method\n"
        unless ($message->{id} || '') eq $id;

      if ($message->{ok}) {
        return $message->{result} || {};
      }

      die "$method failed: " . ($message->{error}{code} || 'unknown') . ': '
        . ($message->{error}{message} || 'unknown error');
    }

    if (($message->{type} || '') eq 'request' && ($message->{method} || '') eq 'runtime.shutdown') {
      $self->_handle_runtime_shutdown($message);
      die '__shutdown__';
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.fatal') {
      die "runtime fatal: " . ($message->{params}{code} || 'unknown');
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.subscription_event') {
      $self->_handle_subscription_event($message->{params} || {});
      next;
    }

    die "Unexpected message while awaiting response for $method\n";
  }
}

sub _read_runtime_chunk {
  my ($self) = @_;
  my $bytes = sysread(STDIN, my $chunk, 4096);
  die "unexpected EOF on runtime stdin\n"
    unless defined $bytes && $bytes > 0;

  push @{$self->{pending_messages}}, @{$self->{protocol}->feed($chunk)};
  return $bytes;
}

sub _drain_pending_runtime_messages {
  my ($self) = @_;
  my $count = 0;

  while (@{$self->{pending_messages}}) {
    my $message = shift @{$self->{pending_messages}};
    $count++;

    if (($message->{type} || '') eq 'request' && ($message->{method} || '') eq 'runtime.shutdown') {
      $self->_handle_runtime_shutdown($message);
      next;
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.fatal') {
      die "runtime fatal: " . ($message->{params}{code} || 'unknown') . "\n";
    }

    if (($message->{type} || '') eq 'notification' && ($message->{method} || '') eq 'runtime.subscription_event') {
      $self->_handle_subscription_event($message->{params} || {});
      next;
    }

    die "Unexpected runtime message in IRC server loop\n";
  }

  return $count;
}

sub _next_runtime_message {
  my ($self) = @_;

  while (!@{$self->{pending_messages}}) {
    $self->_read_runtime_chunk;
  }

  return shift @{$self->{pending_messages}};
}

sub _parse_irc_message {
  my ($self, $line) = @_;
  my %message = (
    raw_line => $line,
    params   => [],
  );

  if ($line =~ s/\A\@(\S+)\s+//) {
    $message{tags} = $self->_parse_irc_tags($1);
  }

  if ($line =~ s/\A:([^ ]+)\s+//) {
    my $prefix = $1;
    $message{prefix} = $prefix;
    if ($prefix =~ /\A([^!@]+)!([^@]+)\@(.+)\z/) {
      @message{qw(prefix_nick prefix_user prefix_host)} = ($1, $2, $3);
    } else {
      $message{prefix_nick} = $prefix;
    }
  }

  my ($command, $rest) = split(/ /, $line, 2);
  return undef unless defined $command && length $command;
  $message{command} = uc($command);
  $rest = '' unless defined $rest;

  while (length $rest) {
    $rest =~ s/\A +//;
    last unless length $rest;

    if ($rest =~ s/\A:(.*)\z//) {
      push @{$message{params}}, $1;
      last;
    }

    if ($rest =~ s/\A([^ ]+)//) {
      push @{$message{params}}, $1;
      next;
    }

    last;
  }

  return \%message;
}

sub _parse_irc_tags {
  my ($self, $raw) = @_;
  my %tags;
  for my $entry (split /;/, $raw) {
    my ($name, $value) = split /=/, $entry, 2;
    next unless defined $name && length $name;
    $tags{$name} = defined $value ? $value : '';
  }
  return \%tags;
}

sub _first_tag_values {
  my ($self, $tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    next if exists $values{$tag->[0]};
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

sub _channel_object_id {
  my ($self, $channel) = @_;
  return 'irc:' . $self->{config}{network} . ':' . $channel;
}

sub _channel_state {
  my ($self, $channel) = @_;
  return $self->{channels}{$channel} ||= {
    members       => {},
    visible_nicks => {},
  };
}

sub _add_visible_nick {
  my ($self, $channel, $nick) = @_;
  return 0 unless defined $nick && !ref($nick) && length($nick);

  my $state = $self->_channel_state($channel);
  $state->{visible_nicks}{$nick} ||= 0;
  $state->{visible_nicks}{$nick}++;
  return $state->{visible_nicks}{$nick};
}

sub _remove_visible_nick {
  my ($self, $channel, $nick) = @_;
  return 0 unless defined $nick && !ref($nick) && length($nick);
  my $state = $self->{channels}{$channel}
    or return 0;
  return 0 unless exists $state->{visible_nicks}{$nick};

  $state->{visible_nicks}{$nick}--;
  delete $state->{visible_nicks}{$nick}
    if $state->{visible_nicks}{$nick} <= 0;
  return 1;
}

sub _rename_visible_nick {
  my ($self, $channel, %args) = @_;
  my $old_nick = $args{old_nick};
  my $new_nick = $args{new_nick};
  return 0 unless defined $old_nick && !ref($old_nick) && length($old_nick);
  return 0 unless defined $new_nick && !ref($new_nick) && length($new_nick);

  my $state = $self->{channels}{$channel}
    or return 0;
  my $count = delete $state->{visible_nicks}{$old_nick}
    or return 0;
  $state->{visible_nicks}{$new_nick} ||= 0;
  $state->{visible_nicks}{$new_nick} += $count;
  return $count;
}

sub _rename_visible_nick_everywhere {
  my ($self, %args) = @_;
  my $count = 0;

  for my $channel (sort keys %{$self->{channels}}) {
    $count += $self->_rename_visible_nick(
      $channel,
      old_nick => $args{old_nick},
      new_nick => $args{new_nick},
    ) || 0;
  }

  return $count;
}

sub _rename_client_channels {
  my ($self, $client, %args) = @_;
  return 0 unless ref($client) eq 'HASH';

  my $count = 0;
  for my $channel (sort keys %{$client->{joined_channels} || {}}) {
    $count += $self->_rename_visible_nick(
      $channel,
      old_nick => $args{old_nick},
      new_nick => $args{new_nick},
    ) || 0;
  }

  return $count;
}

sub _visible_nicks_for_channel {
  my ($self, $channel) = @_;
  my $state = $self->{channels}{$channel}
    or return ();

  return sort grep {
    defined $_ && length $_ && ($state->{visible_nicks}{$_} || 0) > 0
  } keys %{$state->{visible_nicks} || {}};
}

sub _send_join_bootstrap {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $state = $self->{channels}{$channel}
    or return 0;

  if (defined $state->{topic_line} && length $state->{topic_line}) {
    $self->_send_client_line($client_id, $state->{topic_line});
  }

  my @nicks = $self->_visible_nicks_for_channel($channel);
  if (!grep { $_ eq $client->{nick} } @nicks) {
    push @nicks, $client->{nick};
    @nicks = sort @nicks;
  }

  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 353 %s = %s :%s',
      $self->{config}{server_name},
      $client->{nick},
      $channel,
      join(' ', @nicks),
    ),
  );
  $self->_send_client_line(
    $client_id,
    sprintf(
      ':%s 366 %s %s :End of /NAMES list.',
      $self->{config}{server_name},
      $client->{nick},
      $channel,
    ),
  );

  return 1;
}

sub _channel_name_from_object_id {
  my ($self, $object_id) = @_;
  return undef unless defined $object_id && !ref($object_id);

  my $prefix = 'irc:' . $self->{config}{network} . ':';
  return undef unless index($object_id, $prefix) == 0;

  my $channel = substr($object_id, length($prefix));
  return undef unless $self->_is_channel_name($channel);
  return $channel;
}

sub _is_channel_name {
  my ($self, $value) = @_;
  return defined $value
    && !ref($value)
    && $value =~ /\A[#&][^\x00\x07\r\n ,:]+\z/
      ? 1
      : 0;
}

sub _broadcast_channel_line {
  my ($self, $channel, $line) = @_;
  my $state = $self->{channels}{$channel}
    or return 0;

  return $self->_send_line_to_client_ids(
    [ grep { exists $self->{clients}{$_} } sort keys %{$state->{members}} ],
    $line,
  );
}

sub _shared_client_ids_for_channels {
  my ($self, $channels, %args) = @_;
  my %client_ids;

  for my $channel (@{$channels || []}) {
    my $state = $self->{channels}{$channel}
      or next;
    for my $client_id (keys %{$state->{members} || {}}) {
      next if defined $args{exclude_client_id} && $client_id eq $args{exclude_client_id};
      next unless exists $self->{clients}{$client_id};
      next unless $self->{clients}{$client_id}{registered};
      $client_ids{$client_id} = 1;
    }
  }

  return sort keys %client_ids;
}

sub _shared_client_ids_for_client {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return ();
  my @channels = sort keys %{$client->{joined_channels} || {}};
  return ($client_id) unless @channels;
  return $self->_shared_client_ids_for_channels(\@channels);
}

sub _shared_client_ids_for_nick {
  my ($self, $nick) = @_;
  return () unless defined $nick && !ref($nick) && length($nick);

  my @channels = grep {
    ($self->{channels}{$_}{visible_nicks}{$nick} || 0) > 0
  } sort keys %{$self->{channels}};
  return $self->_shared_client_ids_for_channels(\@channels);
}

sub _send_line_to_client_ids {
  my ($self, $client_ids, $line) = @_;
  my $count = 0;

  for my $client_id (@{$client_ids || []}) {
    next unless exists $self->{clients}{$client_id};
    $self->_send_client_line($client_id, $line);
    $count++;
  }

  return $count;
}

sub _send_client_line {
  my ($self, $client_id, $line) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $payload = $line . "\r\n";
  my $offset = 0;
  while ($offset < length $payload) {
    my $written = syswrite($client->{socket}, $payload, length($payload) - $offset, $offset);
    die "failed to write IRC line: $!\n"
      unless defined $written;
    $offset += $written;
  }

  return 1;
}

sub _close_all_clients {
  my ($self) = @_;
  for my $client_id (keys %{$self->{clients}}) {
    my $client = delete $self->{clients}{$client_id};
    $self->_release_client_nick(
      $client_id,
      nick => ($client ? $client->{nick} : undef),
    );
    close $client->{socket}
      if defined $client && defined $client->{socket};
  }
  $self->{channels} = {};
  $self->{nick_to_client_id} = {};
  return 1;
}

sub _close_listen_socket {
  my ($self) = @_;
  return 1 unless defined $self->{listener_socket};
  close delete $self->{listener_socket};
  return 1;
}

sub _is_listener_socket {
  my ($self, $handle) = @_;
  return defined $self->{listener_socket}
    && defined $handle
    && defined fileno($self->{listener_socket})
    && defined fileno($handle)
    && fileno($self->{listener_socket}) == fileno($handle)
      ? 1
      : 0;
}

sub _is_runtime_stdin {
  my ($self, $handle) = @_;
  return defined $handle
    && defined fileno($handle)
    && defined fileno(STDIN)
    && fileno($handle) == fileno(STDIN)
      ? 1
      : 0;
}

sub _client_id_for_handle {
  my ($self, $handle) = @_;
  return undef unless defined $handle && defined fileno($handle);

  for my $client_id (keys %{$self->{clients}}) {
    my $socket = $self->{clients}{$client_id}{socket};
    next unless defined $socket && defined fileno($socket);
    return $client_id if fileno($socket) == fileno($handle);
  }

  return undef;
}

sub _log {
  my ($self, %args) = @_;
  $self->_send_message(
    Overnet::Program::Protocol::build_notification(
      method => 'program.log',
      params => {
        level   => $args{level} || 'info',
        message => $args{message} || '',
        (defined $args{context} ? (context => $args{context}) : ()),
      },
    )
  );
}

sub _health {
  my ($self, %args) = @_;
  $self->_send_message(
    Overnet::Program::Protocol::build_notification(
      method => 'program.health',
      params => {
        status  => $args{status},
        (defined $args{message} ? (message => $args{message}) : ()),
        (defined $args{details} ? (details => $args{details}) : ()),
      },
    )
  );
}

sub _send_message {
  my ($self, $message) = @_;
  my $frame = $self->{protocol}->encode_message($message);
  my $offset = 0;
  while ($offset < length $frame) {
    my $written = syswrite(STDOUT, $frame, length($frame) - $offset, $offset);
    die "failed to write runtime protocol frame: $!\n"
      unless defined $written;
    $offset += $written;
  }

  return 1;
}

1;

=head1 NAME

Overnet::Program::IRC::Server - Supervised listening IRC server for Overnet

=head1 DESCRIPTION

Accepts IRC client connections, maps inbound IRC commands through the runtime
adapter service, signs candidate Overnet events with Net::Nostr, emits them
through the runtime validation boundary, and fans subscribed Overnet channel
items back out as IRC lines.

=cut
