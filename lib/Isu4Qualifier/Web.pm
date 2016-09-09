package Isu4Qualifier::Web;

use strict;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Digest::SHA qw/ sha256_hex /;
use Data::Dumper;
use Redis::Fast;
use JSON::XS;

sub config {
  my ($self) = @_;
  $self->{_config} ||= {
    user_lock_threshold => $ENV{'ISU4_USER_LOCK_THRESHOLD'} || 3,
    ip_ban_threshold => $ENV{'ISU4_IP_BAN_THRESHOLD'} || 10
  };
};

sub json_driver {
    my ($self) = @_;
    $self->{_json_driver} ||= JSON::XS->new;
}

sub redis {
    my ($self) = @_;
    $self->{_redis} ||= Redis::Fast->new( sock => '/tmp/redis.sock' );
}

sub db {
  my ($self) = @_;
  my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
  my $port = $ENV{ISU4_DB_PORT} || 3306;
  my $username = $ENV{ISU4_DB_USER} || 'root';
  my $password = $ENV{ISU4_DB_PASSWORD};
  my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

  $self->{_db} ||= do {
    DBIx::Sunny->connect(
      "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
        RaiseError => 1,
        PrintError => 0,
        AutoInactiveDestroy => 1,
        mysql_enable_utf8   => 1,
        mysql_auto_reconnect => 1,
      },
    );
  };
}

sub calculate_password_hash {
  my ($password, $salt) = @_;
  sha256_hex($password . ':' . $salt);
};

sub user_locked {
  my ($self, $user) = @_;
  my $cnt = $self->redis->hget("login:user_id:succfail", $user->{id}) || 0;
  return $self->config->{user_lock_threshold} <= $cnt;
};

sub ip_banned {
  my ($self, $ip) = @_;
  my $cnt = $self->redis->hget("login:ip:succfail", $ip) || 0;
  return $self->config->{ip_ban_threshold} <= $cnt;
};

sub attempt_login {
  my ($self, $login, $password, $ip) = @_;
  my $user = $self->db->select_row('SELECT * FROM users WHERE login = ?', $login);

  if ($self->ip_banned($ip)) {
    $self->login_log(0, $login, $ip, $user ? $user->{id} : undef);
    return undef, 'banned';
  }

  if ($self->user_locked($user)) {
    $self->login_log(0, $login, $ip, $user->{id});
    return undef, 'locked';
  }

  if ($user && calculate_password_hash($password, $user->{salt}) eq $user->{password_hash}) {
    $self->login_log(1, $login, $ip, $user->{id});
    return $user, undef;
  }
  elsif ($user) {
    $self->login_log(0, $login, $ip, $user->{id});
    return undef, 'wrong_password';
  }
  else {
    $self->login_log(0, $login, $ip);
    return undef, 'wrong_login';
  }
};

sub current_user {
  my ($self, $user_id) = @_;

  $self->db->select_row('SELECT * FROM users WHERE id = ?', $user_id);
};

sub last_login {
  my ($self, $user_id) = @_;
  my $slk = sprintf "login:user_id:%d", $user_id;
  my @rows = $self->redis->lrange($slk, 0, 1);
  my $user = $self->json_driver->decode($rows[-1]);
  return $user;
};

sub banned_ips {
  my ($self) = @_;
  my @ips;
  my $threshold = $self->config->{ip_ban_threshold};

  my %data = $self->redis->hgetall("login:ip:succfail");
  while (my ($ip, $cnt) = each %data) {
      if ($threshold <= $cnt) {
          push @ips, $ip;
      }
  }
  return [ sort @ips ];
};

sub locked_users {
  my ($self) = @_;
  my @user_ids;
  my $threshold = $self->config->{user_lock_threshold};

  my @tmp_user_id;
  my %data = $self->redis->hgetall("login:user_id:succfail");
  while (my ($user_id, $cnt) = each %data) {
      if ($threshold <= $cnt) {
          push @tmp_user_id, $user_id;
      }
  }
  my $lus = $self->db->select_all('SELECT login FROM users WHERE id IN(' . join(',', @tmp_user_id) . ')');
  for my $r (@$lus) {
      push @user_ids, $r->{login};
  }
  return [ sort @user_ids ];
};

sub login_log {
  my ($self, $succeeded, $login, $ip, $user_id) = @_;
  # ログインのip成否更新
  if ($succeeded) {
      $self->redis->hset("login:ip:succfail", $ip, 0, sub {});
  } else {
      $self->redis->hincrby("login:ip:succfail", $ip, 1, sub {});
  }

  # ログインのuser_id成否更新
  if ($user_id) {
      if ($succeeded) {
          $self->redis->hset("login:user_id:succfail", $user_id, 0, sub {});
      } else {
        $self->redis->hincrby("login:user_id:succfail", $user_id, 1, sub {});
      }
  }

  # loginの成功記録
  if ($succeeded && $user_id) {
      my $slk = sprintf "login:user_id:%d", $user_id;
      $self->redis->lpush($slk, $self->json_driver->encode({
          created_at => "2016-10-04 00:00:00", # dummy
          user_id => $user_id,
          login => $login,
          ip => $ip,
          succeeded => $succeeded,
      }), sub {});
  }

  $self->redis->wait_all_responses;
};

sub set_flash {
  my ($self, $c, $msg) = @_;
  $c->req->env->{'psgix.session'}->{flash} = $msg;
};

sub pop_flash {
  my ($self, $c, $msg) = @_;
  my $flash = $c->req->env->{'psgix.session'}->{flash};
  delete $c->req->env->{'psgix.session'}->{flash};
  $flash;
};

filter 'session' => sub {
  my ($app) = @_;
  sub {
    my ($self, $c) = @_;
    my $sid = $c->req->env->{'psgix.session.options'}->{id};
    $c->stash->{session_id} = $sid;
    $c->stash->{session}    = $c->req->env->{'psgix.session'};
    $app->($self, $c);
  };
};

get '/' => [qw(session)] => sub {
  my ($self, $c) = @_;

  $c->render('index.tx', { flash => $self->pop_flash($c) });
};

post '/login' => sub {
  my ($self, $c) = @_;
  my $msg;

  my ($user, $err) = $self->attempt_login(
    $c->req->param('login'),
    $c->req->param('password'),
    $c->req->address
  );

  if ($user && $user->{id}) {
    $c->req->env->{'psgix.session'}->{user_id} = $user->{id};
    $c->redirect('/mypage');
  }
  else {
    if ($err eq 'locked') {
      $self->set_flash($c, 'This account is locked.');
    }
    elsif ($err eq 'banned') {
      $self->set_flash($c, "You're banned.");
    }
    else {
      $self->set_flash($c, 'Wrong username or password');
    }
    $c->redirect('/');
  }
};

get '/mypage' => [qw(session)] => sub {
  my ($self, $c) = @_;
  # loginに成功しないとpsgix.sessionにuser_idが入らない、ので、current_userのチェックは不要
  my $user_id = $c->req->env->{'psgix.session'}->{user_id} || 0;
  my $last_login_user = $self->last_login($user_id);
  #my $user = $self->current_user($user_id);
  my $msg;

  if ($last_login_user) {
    $c->render('mypage.tx', { last_login => $last_login_user });
  }
  else {
    $self->set_flash($c, "You must be logged in");
    $c->redirect('/');
  }
};

get '/report' => sub {
  my ($self, $c) = @_;
  $c->render_json({
    banned_ips => $self->banned_ips,
    locked_users => $self->locked_users,
  });
};

1;
