#!/bin/sh

# Test subscribing before publishing. We should get an event.

subevents -p -r 1000000000000000000000000000000000000000000000000000000000000002 -v -n 1 &
sleep 2
psirptest -p -r 1000000000000000000000000000000000000000000000000000000000000002 -f /COPYRIGHT
sleep 2
killall subevents
