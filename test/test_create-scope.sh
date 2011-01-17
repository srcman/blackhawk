#!/bin/sh

# Create a scope by publishing someting with the corresponding FId.
# Then check the /pubsub root directory to see if the FId appeared.
# The last line should show 1.

SID=0000000000000000000000000000000000000000000000000000000000000005
RID=1000000000000000000000000000000000000000000000000000000000000005

psirptest -p -f /COPYRIGHT -c $SID -r $RID
ls -lai /pubsub |grep $SID |wc -l
