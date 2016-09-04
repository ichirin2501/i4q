use FindBin;
use lib "$FindBin::Bin/extlib/lib/perl5";
use lib "$FindBin::Bin/lib";
use File::Basename;
use Plack::Builder;
use Isu4Qualifier::Web;
use Plack::Session::State::Cookie;
use Plack::Session::Store::File;
use Cache::Memcached::Fast;

my $root_dir = File::Basename::dirname(__FILE__);
my $session_dir = "/dev/shm/isu4_session_plack";
mkdir $session_dir;

my $app = Isu4Qualifier::Web->psgi($root_dir);
builder {
  enable 'ReverseProxy';
#  enable 'Static',
#    path => qr!^/(?:stylesheets|images)/!,
#    root => $root_dir . '/public';
  enable 'Session::Simple',
    store => Cache::Memcached::Fast->new({
      servers => [ { address => "localhost:11211",noreply=>0} ],
    }),
    httponly => 1,
    cookie_name => "isu4_session",
    keep_empty => 0
    ;
  $app;
};
