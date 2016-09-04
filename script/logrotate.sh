#!/bin/bash
set -ex

# nginx
mv /var/log/nginx/isucon.access_log.tsv /var/log/nginx/isucon.access_log.tsv.1

# mysql
mv /var/lib/mysql/mysqld-slow.log /var/lib/mysql/mysqld-slow.log.1
