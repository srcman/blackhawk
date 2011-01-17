#!/bin/sh
#
# Conformance testing for versions.
# 

. check_prepare.sh

TEST_VER=$BIN/test_ver.py

check_start

sysctl debug.pubsub_debug_mask=0x0000000000020013

scoped_start
subevd_start
sleep 0.5

check $TEST_VER -b 17385  -s aa:: -r aa::bb -n 20
check $TEST_VER -b 1      -s aa:: -r aa::cc -n 5
check $TEST_VER -b 4095   -s aa:: -r aa::dd -n 5
check $TEST_VER -b 4096   -s aa:: -r aa::ee -n 5
check $TEST_VER -b 4097   -s aa:: -r aa::ff -n 5

check $TEST_VER -b 17385  -s aa:: -r aa::bb -n 5
check $TEST_VER -b 8192   -s aa:: -r aa::bb -n 5 -c

check $TEST_VER -b 8193   -s bb:: -r bb::cc -n 20 -c
check $TEST_VER -b 512000 -s bb:: -r bb::cc -n 5  -c
check $TEST_VER -b 17385  -s bb:: -r aa::bb -n 5  -c

check_end
