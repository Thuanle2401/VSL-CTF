#!/bin/bash

BINARY=/chall/hothothot

while true; do
    socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"$BINARY",stderr
done