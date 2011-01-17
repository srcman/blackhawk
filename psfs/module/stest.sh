#!/bin/sh

echo "Warning! This script is obsolete. Use e.g. reloadps instead."

set -e
# set -x

sync; sync; sync

sleep 1

test -d /pubsub || mkdir /pubsub

SCOPE1=/pubsub/$RID1
RID1=0359675406956079358359646749623905850546897932873495685695456555
RID2=0359675406956079358359646749623905850546897932873495685695456444
PUB=$SCOPE0/$RID
DATA=$PUB/data

killall -vv scoped || true
if mount | grep -q psfs; then
   umount -f /pubsub
fi
if kldstat | grep -q psfs; then
   kldunload psfs
fi
make install
sync; sync; sync; sleep 1
kldload psfs
kldstat |grep psfs
sysctl debug.pubsub_debug_mask=0x0000000000026003 # Directories and vfs
#sysctl debug.pubsub_debug_mask=0x0000000000020093 # Syscalls
#sysctl debug.pubsub_debug_mask=0x0000000000028023 # KNOTES and filters
#sysctl debug.pubsub_debug_mask=0x0000000000028063  # KNOTES, filters, and events
#sysctl debug.pubsub_debug_mask=0xFFFFFFFFFFFFFFFF
echo "Mounting psfs"
sleep 1
mount -t psfs psfs /pubsub
echo "Starting scoped"
sleep 1
scoped -vv &
echo "Performing first psirptests"
sleep 1
#
# Note that (at least this version of) the filesystem is magic.
# mkdir can be *only* used to create scopes
# touch [or creat(2)] can be *only* used to create publications.
# However, creat(2) creates a directory for the RID, not a file.
#
# sleep 1
psirptest -p -r $RID1 -f /COPYRIGHT || true
sleep 1
psirptest -p -r $RID2 -f /COPYRIGHT || true
sleep 1
rm -f /tmp/foobar /tmp/foobar2
psirptest -s -r $RID1 -f /tmp/foobar || true
sleep 1
echo "Warning: scoped still running."
