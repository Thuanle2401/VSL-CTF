#!/bin/sh

BINARY=/hacker/summerStore

while :; do
    socat -dd -T60 tcp-l:1337,reuseaddr,fork,keepalive,su=nobody exec:$BINARY,stderr
done