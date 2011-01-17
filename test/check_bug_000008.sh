#!/bin/sh
#
# Test to catch potential reoccurence of bug 000008
# 

. check_prepare.sh

# Test subscribing to both a SID (a RID for a scope) and a new RID (in
# that scope). Then publish something with the RID. We should get two
# events: one corresponding to the publication and one to the scope.

SID=00::05
RID=10::05
DELAY="sleep 1"

check_start

scoped_start

check $PUBLISH -e 0 $VERB -s $SID -r $RID -l 1
check $DELAY
check ./subevents $VERB -s $SID -r $RID -p -n 1 &
check $DELAY
check ./subevents $VERB -r $SID -p -n 1 &
check $DELAY
check $PUBLISH -e 0 $VERB -s $SID -r $RID -l 1
check $DELAY
    if $verbose; then
	(killall -vv subevents || true) 2>&1 | sed -e 's/^/PREPARE: /'
    else
	(killall -vv subevents || true) 2> /dev/null
    fi

check_end
