use strict;
use warnings;

use Cwd qw(getcwd);
use File::Spec;
use FindBin;
use Test::More;

my $makefile_pl = File::Spec->catfile($FindBin::Bin, '..', 'Makefile.PL');

ok -f $makefile_pl, 'Makefile.PL exists'
  or BAIL_OUT('Makefile.PL is required');

my $args = _capture_makefile_args($makefile_pl);

is $args->{NAME}, 'Overnet::Program::IRC::Server', 'distribution name';
is $args->{DISTNAME}, 'Overnet-IRC-Server', 'CPAN dist name';
is $args->{AUTHOR}, 'Nicholas B. Hubbard <nicholashubbard@posteo.net>', 'author';
is $args->{ABSTRACT}, 'The Overnet IRC server program, implemented in Perl', 'abstract';
is $args->{VERSION_FROM}, 'lib/Overnet/Program/IRC/Server.pm', 'version comes from server module';
is $args->{LICENSE}, 'gpl_3', 'license';
is $args->{MIN_PERL_VERSION}, '5.024', 'minimum Perl version';

is_deeply(
  $args->{PREREQ_PM},
  {
    'IO::Socket::SSL' => 0,
    'Net::Nostr'      => 0,
    'Overnet'         => 0.001,
    'Overnet::Relay'  => 0.001,
  },
  'runtime prerequisites stay on top-level non-core distributions',
);

is_deeply(
  $args->{TEST_REQUIRES} || {},
  {},
  'no extra non-core test-only prerequisites',
);

is_deeply(
  $args->{EXE_FILES},
  [
    'bin/overnet-irc-authority-relay-service.pl',
    'bin/overnet-irc-authority-relay.pl',
    'bin/overnet-irc-chat-client.pl',
    'bin/overnet-irc-local-server.pl',
    'bin/overnet-irc-server.pl',
    'bin/overnet-irc-service.pl',
  ],
  'installable IRC scripts are explicit',
);

is_deeply(
  $args->{META_MERGE},
  {
    resources => {
      repository => 'https://github.com/overnet-project/irc-server',
      bugtracker => 'https://github.com/overnet-project/irc-server/issues',
    },
  },
  'metadata resources point at the public repo',
);

is_deeply(
  $args->{test},
  {
    TESTS => join(
      ' ',
      qw(
        t/00-load.t
        t/bin-syntax.t
        t/makemaker-metadata.t
      )
    ),
  },
  'default test suite stays CPAN-safe',
);

done_testing;

sub _capture_makefile_args {
  my ($makefile_pl) = @_;
  my $args;
  my $cwd = getcwd();
  my ($volume, $dirs) = File::Spec->splitpath($makefile_pl);
  my $repo_root = File::Spec->catpath($volume, $dirs, '');
  $repo_root =~ s{/$}{};

  {
    require ExtUtils::MakeMaker;

    no warnings qw(redefine once);
    local *ExtUtils::MakeMaker::WriteMakefile = sub {
      $args = {@_};
      return 1;
    };
    local *main::WriteMakefile = \&ExtUtils::MakeMaker::WriteMakefile;

    chdir $repo_root or die "unable to chdir to $repo_root: $!";
    my $rv = do $makefile_pl;
    my $error = $@;
    chdir $cwd or die "unable to restore cwd to $cwd: $!";

    die $error if $error;
    die "unable to load $makefile_pl: $!" unless defined $rv;
  }

  return $args;
}
