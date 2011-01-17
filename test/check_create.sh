#!/bin/sh
#
# Conformance testing for the create system call.
# 

. check_prepare.sh

check_start

echo "START: $0: Testing metadata length..."
check $CREATE  -e 22 $VERB -k 1
check $CREATE  -e 22 $VERB -k 0
check $CREATE  -e 22 $VERB -k -1
check $CREATE  -e 0  $VERB -k 4096
check $CREATE  -e 22 $VERB -k 4097

echo "START: $0: Testing data length..."
check $CREATE  -e 22 $VERB -k 1024 -l -1
check $CREATE  -e 0  $VERB -k 1024 -l 0 
check $CREATE  -e 0  $VERB -k 1024 -l 1
check $CREATE  -e 0  $VERB -k 1024 -l 4096
check $CREATE  -e 0  $VERB -k 1024 -l 4097
# XXX: We currently limit the published objects to 125 pages
check $CREATE  -e 0  $VERB -k 1024 -l 512000
check $CREATE  -e 22 $VERB -k 1024 -l 512001
# XXX: We previously limited the published objects to one megabyte.
check $CREATE  -e 22 $VERB -k 1024 -l 1048576
check $CREATE  -e 22 $VERB -k 1024 -l 1048577

echo "START: $0: Testing metadata pointer..."
check $CREATE  -e 0  $VERB -k 1024 -m 1
check $CREATE  -e 0  $VERB -k 1024 -m 0x100000000
check $CREATE  -e 0  $VERB -k 1024 -m 0x800500000
check $CREATE  -e 0  $VERB -k 1024 -m 0x800530000
check $CREATE  -e 0  $VERB -k 1024 -m 0x100000000000
check $CREATE  -e 0  $VERB -k 1024 -m 0x700000000000
check $CREATE  -e 12 $VERB -k 1024 -m 0x7fffffff0000
check $CREATE  -e 12 $VERB -k 1024 -m 0x7ffffffff000
check $CREATE  -e 12 $VERB -k 1024 -m 0x800000000000
check $CREATE  -e 12 $VERB -k 1024 -m 0x1000000000000
check $CREATE  -e 12 $VERB -k 1024 -m 0x8000000000000
check $CREATE  -e 12 $VERB -k 1024 -m 0xf000000000000

echo "START: $0: Testing data pointer..."
check $CREATE  -e 0  $VERB -k 1024 -l 1024 -d 1
check $CREATE  -e 0  $VERB -k 1024 -l 1024 -d 0x100000000
check $CREATE  -e 0  $VERB -k 1024 -l 1024 -d 0x800500000
check $CREATE  -e 0  $VERB -k 1024 -l 1024 -d 0x800530000
check $CREATE  -e 0  $VERB -k 1024 -l 1024 -d 0x100000000000
check $CREATE  -e 0  $VERB -k 1024 -l 1024 -d 0x700000000000
check $CREATE  -e 12 $VERB -k 1024 -l 1024 -d 0x7fffffff0000
check $CREATE  -e 12 $VERB -k 1024 -l 1024 -d 0x7ffffffff000
check $CREATE  -e 12 $VERB -k 1024 -l 1024 -d 0x800000000000
check $CREATE  -e 12 $VERB -k 1024 -l 1024 -d 0x1000000000000
check $CREATE  -e 12 $VERB -k 1024 -l 1024 -d 0x8000000000000
check $CREATE  -e 12 $VERB -k 1024 -l 1024 -d 0xf000000000000

check_end
