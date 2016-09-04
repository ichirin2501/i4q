#!/bin/env perl
#
use strict;
use warnings;
use Redis::Fast;
use JSON::XS;

my $jd    = JSON::XS->new;
my $redis = Redis::Fast->new;

my $header = <>; # header

for my $line (<>) {
    chomp $line;
    my ($id,$created_at,$user_id,$login,$ip,$succeeded) = split/\t/, $line;

    # loginのipの連続失敗記録, hash型
    my $bankey = sprintf "login:ip:succfail", $ip;
    if ($succeeded) {
        $redis->hset($bankey, $ip, 0, sub {});
    } else {
        $redis->hincrby($bankey, $ip, 1, sub {});
    }

    # loginの成功記録
    my $slk = sprintf "login:user_id:%d", $user_id;
    if ($succeeded) {
        $redis->lpush($slk, $jd->encode({
            id => $id,
            created_at => $created_at,
            user_id => $user_id,
            login => $login,
            ip => $ip,
            succeeded => $succeeded,
        }), sub {});
    }
}

$redis->wait_all_responses;
