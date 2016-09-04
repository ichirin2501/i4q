#!/bin/bash

cd $(dirname $0)
cd ..
# root

exec carton exec -- perl ./script/redisinit.pl
