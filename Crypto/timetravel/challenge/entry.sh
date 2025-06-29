#!/bin/sh

BINARY=/app/main.py

while :; do
    socat -dd -T60 tcp-l:1337,reuseaddr,fork,su=nobody "exec:python3 $BINARY,stderr"
done
