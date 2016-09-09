#!/bin/sh
set -x
set -e
cd $(dirname $0)

myuser=root
mydb=isu4_qualifier
myhost=127.0.0.1
myport=3306
mysql -h ${myhost} -P ${myport} -u ${myuser} -e "DROP DATABASE IF EXISTS ${mydb}; CREATE DATABASE ${mydb}"
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/schema.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_users.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_log.sql

# redis init
redis-cli -s /tmp/redis.sock flushdb
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} -e 'SELECT id,created_at,user_id,login,ip,succeeded FROM login_log ORDER BY id' | ./env.sh /home/isucon/webapp/perl/script/redisinit.sh

