#!/bin/sh
#
# Test to catch potential reoccurence of bug 000010
# 

. check_prepare.sh

check_start

scoped_start

sysctl debug.pubsub_debug_mask=0xFFFFFFFFFFFFFFFF >/dev/null
subscribe -r ::10 > /dev/null
if dmesg | tail -50 | grep -q 'scope_access: WARNING' 2>/dev/null; then
   echo "Error"
   exit 1
else
   if $verbose; then
      echo "Ok"
   fi
fi

check_end
