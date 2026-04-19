package Overnet::Program::IRC::Renderer;

use strict;
use warnings;

our $VERSION = '0.001';

sub authenticate_payload_lines {
  my (%args) = @_;
  my $remaining = defined($args{payload}) ? $args{payload} : '';
  my @lines;

  while (length($remaining) > 400) {
    push @lines, 'AUTHENTICATE ' . substr($remaining, 0, 400, '');
  }

  if (length $remaining) {
    push @lines, 'AUTHENTICATE ' . $remaining;
  } else {
    push @lines, 'AUTHENTICATE +';
  }

  return \@lines;
}

sub sasl_success_line {
  my (%args) = @_;
  return sprintf(
    ':%s 903 %s :SASL authentication successful',
    $args{server_name},
    $args{nick},
  );
}

sub sasl_fail_line {
  my (%args) = @_;
  return sprintf(
    ':%s 904 %s :SASL authentication failed',
    $args{server_name},
    $args{nick},
  );
}

sub unknown_command_line {
  my (%args) = @_;
  return sprintf(
    ':%s 421 %s %s :Unknown command',
    $args{server_name},
    $args{nick},
    $args{command},
  );
}

sub registration_prelude_lines {
  my (%args) = @_;
  return [
    sprintf(
      ':%s 001 %s :Welcome to Overnet IRC',
      $args{server_name},
      $args{nick},
    ),
    sprintf(
      ':%s 005 %s %s :are supported by this server',
      $args{server_name},
      $args{nick},
      $args{isupport_tokens},
    ),
    sprintf(
      ':%s 422 %s :MOTD File is missing',
      $args{server_name},
      $args{nick},
    ),
  ];
}

sub nonickname_given_line {
  my (%args) = @_;
  return sprintf(
    ':%s 431 %s :No nickname given',
    $args{server_name},
    $args{nick},
  );
}

sub not_registered_line {
  my (%args) = @_;
  return sprintf(
    ':%s 451 * :You have not registered',
    $args{server_name},
  );
}

sub need_more_params_line {
  my (%args) = @_;
  return sprintf(
    ':%s 461 %s %s :Not enough parameters',
    $args{server_name},
    $args{nick},
    $args{command},
  );
}

sub server_notice_line {
  my (%args) = @_;
  return sprintf(
    ':%s NOTICE %s :%s',
    $args{server_name},
    $args{nick},
    $args{text},
  );
}

sub no_such_nick_line {
  my (%args) = @_;
  return sprintf(
    ':%s 401 %s %s :No such nick/channel',
    $args{server_name},
    $args{nick},
    $args{target_nick},
  );
}

sub no_such_channel_line {
  my (%args) = @_;
  return sprintf(
    ':%s 403 %s %s :No such channel',
    $args{server_name},
    $args{nick},
    $args{channel},
  );
}

sub not_on_channel_line {
  my (%args) = @_;
  return sprintf(
    ':%s 442 %s %s :You\'re not on that channel',
    $args{server_name},
    $args{nick},
    $args{channel},
  );
}

sub cannot_send_to_channel_line {
  my (%args) = @_;
  return sprintf(
    ':%s 404 %s %s :Cannot send to channel',
    $args{server_name},
    $args{nick},
    $args{channel},
  );
}

sub chan_op_privs_needed_line {
  my (%args) = @_;
  return sprintf(
    ':%s 482 %s %s :You\'re not channel operator',
    $args{server_name},
    $args{nick},
    $args{channel},
  );
}

sub cannot_join_channel_line {
  my (%args) = @_;
  my $numeric = 473;
  $numeric = 474 if defined($args{reason}) && $args{reason} eq '+b';
  $numeric = 475 if defined($args{reason}) && $args{reason} eq '+k';
  $numeric = 471 if defined($args{reason}) && $args{reason} eq '+l';
  my $reason = 'Cannot join channel';
  $reason .= ' (' . $args{reason} . ')'
    if defined($args{reason}) && length($args{reason});

  return sprintf(
    ':%s %d %s %s :%s',
    $args{server_name},
    $numeric,
    $args{nick},
    $args{channel},
    $reason,
  );
}

sub ban_list_entry_line {
  my (%args) = @_;
  return sprintf(
    ':%s 367 %s %s %s %s 0',
    $args{server_name},
    $args{nick},
    $args{channel},
    $args{ban_mask},
    $args{server_name},
  );
}

sub end_of_ban_list_line {
  my (%args) = @_;
  return sprintf(
    ':%s 368 %s %s :End of channel ban list',
    $args{server_name},
    $args{nick},
    $args{channel},
  );
}

sub exception_list_entry_line {
  my (%args) = @_;
  return sprintf(
    ':%s 348 %s %s %s %s 0',
    $args{server_name},
    $args{nick},
    $args{channel},
    $args{exception_mask},
    $args{server_name},
  );
}

sub end_of_exception_list_line {
  my (%args) = @_;
  return sprintf(
    ':%s 349 %s %s :End of channel exception list',
    $args{server_name},
    $args{nick},
    $args{channel},
  );
}

sub invite_exception_list_entry_line {
  my (%args) = @_;
  return sprintf(
    ':%s 346 %s %s %s %s 0',
    $args{server_name},
    $args{nick},
    $args{channel},
    $args{invite_exception_mask},
    $args{server_name},
  );
}

sub end_of_invite_exception_list_line {
  my (%args) = @_;
  return sprintf(
    ':%s 347 %s %s :End of channel invite exception list',
    $args{server_name},
    $args{nick},
    $args{channel},
  );
}

sub inviting_line {
  my (%args) = @_;
  return sprintf(
    ':%s 341 %s %s %s',
    $args{server_name},
    $args{nick},
    $args{target_nick},
    $args{channel},
  );
}

sub channel_mode_is_line {
  my (%args) = @_;
  my $suffix = join ' ',
    grep { defined($_) && !ref($_) && length($_) }
    @{$args{mode_args} || []};
  return sprintf(
    ':%s 324 %s %s %s%s',
    $args{server_name},
    $args{nick},
    $args{channel},
    $args{channel_modes},
    (length($suffix) ? ' ' . $suffix : ''),
  );
}

sub user_mode_is_line {
  my (%args) = @_;
  return sprintf(
    ':%s 221 %s +',
    $args{server_name},
    $args{nick},
  );
}

sub lusers_reply_lines {
  my (%args) = @_;
  return [
    sprintf(
      ':%s 251 %s :There are %d users and 0 services on 1 server',
      $args{server_name},
      $args{nick},
      $args{registered_users},
    ),
    sprintf(
      ':%s 252 %s 0 :operator(s) online',
      $args{server_name},
      $args{nick},
    ),
    sprintf(
      ':%s 253 %s 0 :unknown connection(s)',
      $args{server_name},
      $args{nick},
    ),
    sprintf(
      ':%s 254 %s %d :channels formed',
      $args{server_name},
      $args{nick},
      $args{channels},
    ),
    sprintf(
      ':%s 255 %s :I have %d clients and 1 server',
      $args{server_name},
      $args{nick},
      $args{connected_clients},
    ),
  ];
}

sub list_reply_lines {
  my (%args) = @_;
  my @lines = (
    sprintf(
      ':%s 321 %s Channel :Users Name',
      $args{server_name},
      $args{nick},
    ),
  );

  for my $entry (@{$args{entries} || []}) {
    push @lines, sprintf(
      ':%s 322 %s %s %d :%s',
      $args{server_name},
      $args{nick},
      $entry->{channel},
      $entry->{visible_users},
      $entry->{topic},
    );
  }

  push @lines, sprintf(
    ':%s 323 %s :End of /LIST',
    $args{server_name},
    $args{nick},
  );

  return \@lines;
}

sub topic_is_line {
  my (%args) = @_;
  return sprintf(
    ':%s 332 %s %s :%s',
    $args{server_name},
    $args{nick},
    $args{channel},
    $args{topic},
  );
}

sub no_topic_line {
  my (%args) = @_;
  return sprintf(
    ':%s 331 %s %s :No topic is set',
    $args{server_name},
    $args{nick},
    $args{channel},
  );
}

sub userhost_line {
  my (%args) = @_;
  return sprintf(
    ':%s 302 %s :%s',
    $args{server_name},
    $args{nick},
    join(' ', @{$args{entries} || []}),
  );
}

sub who_list_lines {
  my (%args) = @_;
  my @lines;

  for my $entry (@{$args{entries} || []}) {
    push @lines, sprintf(
      ':%s 352 %s %s %s %s %s %s H :0 %s',
      $args{server_name},
      $args{nick},
      $args{channel},
      $entry->{username},
      $entry->{host},
      $args{server_name},
      $entry->{nick},
      $entry->{realname},
    );
  }

  push @lines, sprintf(
    ':%s 315 %s %s :End of /WHO list.',
    $args{server_name},
    $args{nick},
    $args{channel},
  );

  return \@lines;
}

sub whois_reply_lines {
  my (%args) = @_;
  my $entry = $args{entry} || {};
  return [
    sprintf(
      ':%s 311 %s %s %s %s * :%s',
      $args{server_name},
      $args{nick},
      $entry->{nick},
      $entry->{username},
      $entry->{host},
      $entry->{realname},
    ),
    sprintf(
      ':%s 312 %s %s %s :%s',
      $args{server_name},
      $args{nick},
      $entry->{nick},
      $args{server_name},
      $args{server_description},
    ),
    sprintf(
      ':%s 318 %s %s :End of /WHOIS list.',
      $args{server_name},
      $args{nick},
      $entry->{nick},
    ),
  ];
}

sub nick_in_use_line {
  my (%args) = @_;
  return sprintf(
    ':%s 433 %s %s :Nickname is already in use',
    $args{server_name},
    $args{nick},
    $args{attempted_nick},
  );
}

sub names_list_lines {
  my (%args) = @_;
  return [
    sprintf(
      ':%s 353 %s = %s :%s',
      $args{server_name},
      $args{nick},
      $args{channel},
      join(' ', @{$args{names} || []}),
    ),
    sprintf(
      ':%s 366 %s %s :End of /NAMES list.',
      $args{server_name},
      $args{nick},
      $args{channel},
    ),
  ];
}

1;
