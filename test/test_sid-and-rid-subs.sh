#!/bin/sh

# Test subscribing to both a SID (a RID for a scope) and a new RID (in
# that scope). Then publish something with the RID. We should get two
# events: one corresponding to the publication and one to the scope.

SID=0000000000000000000000000000000000000000000000000000000000000005
RID=1000000000000000000000000000000000000000000000000000000000000005

#mkdir /pubsub/$SID
psirptest -p -f /COPYRIGHT -c $SID -r $RID
sleep 1

subevents -v -s $SID -r $RID -p -n 1 &
sleep 1
subevents -v -r $SID -p -n 1 &
sleep 1
psirptest -p -c $SID -r $RID -f /COPYRIGHT
sleep 1
killall subevents
