use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../../overnet-code/lib";
use lib "$FindBin::Bin/../../overnet-code/local/lib/perl5";

use Overnet::Program::IRC::Server;

my $server = Overnet::Program::IRC::Server->new;
$server->run;

