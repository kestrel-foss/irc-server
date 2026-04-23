use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME             => 'Overnet::Program::IRC::Server',
  DISTNAME         => 'Overnet-IRC-Server',
  AUTHOR           => 'Nicholas B. Hubbard <nicholashubbard@posteo.net>',
  ABSTRACT         => 'The Overnet IRC server program, implemented in Perl',
  VERSION_FROM     => 'lib/Overnet/Program/IRC/Server.pm',
  LICENSE          => 'gpl_3',
  MIN_PERL_VERSION => '5.024',
  PREREQ_PM        => {
    'IO::Socket::SSL' => 0,
    'Net::Nostr'      => 0,
    'Overnet'         => 0.001,
    'Overnet::Relay'  => 0.001,
  },
  EXE_FILES        => [
    'bin/overnet-irc-auth.pl',
    'bin/overnet-irc-authority-relay-service.pl',
    'bin/overnet-irc-authority-relay.pl',
    'bin/overnet-irc-chat-client.pl',
    'bin/overnet-irc-local-server.pl',
    'bin/overnet-irc-server.pl',
    'bin/overnet-irc-service.pl',
  ],
  test => {
    TESTS => join(
      ' ',
      qw(
        t/00-load.t
        t/bin-syntax.t
        t/irc-auth-cli.t
        t/irc-auth-helper.t
        t/makemaker-metadata.t
        t/manifest-skip-policy.t
        t/readme-auth.t
      )
    ),
  },
  META_MERGE => {
    resources => {
      repository => 'https://github.com/overnet-project/irc-server',
      bugtracker => 'https://github.com/overnet-project/irc-server/issues',
    },
  },
);
