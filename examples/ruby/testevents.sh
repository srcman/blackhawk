# Test script that publishes data. Can be used together with pubsubevents.rb.

dd if=/dev/urandom of=a.file bs=1 count=1023
dd if=/dev/urandom of=b.file bs=1 count=2047
dd if=/dev/urandom of=c.file bs=1 count=4095
dd if=/dev/urandom of=d.file bs=1 count=8191

psirptest -p -c aa:: -r ::1001 -f a.file
sleep 0.5
psirptest -p -c aa:: -r ::1001 -f b.file
sleep 0.2
psirptest -p -c aa:: -r ::1001 -f c.file
sleep 0.2
psirptest -p -c aa:: -r ::1001 -f d.file
sleep 0.2
psirptest -p -c aa:: -r ::1002 -f b.file
sleep 0.2
psirptest -p -c aa:: -r ::1003 -f c.file
sleep 0.2
psirptest -p -c aa:: -r ::1004 -f d.file
sleep 0.2
psirptest -p -c aa:: -r ::1004 -f a.file
sleep 0.2

rm a.file b.file c.file d.file
