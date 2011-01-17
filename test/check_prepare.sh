#!/bin/sh
#
# Prepare for a test case.  Start afresh
#

BIN=.
MODULE_DIR=../psfs/module
SCOPED=../psfs/scoped/scoped
SUBEVD=../helpers/subevd/subevd
DATA=check_files
verbose=false
PUBLISH=$BIN/publish
CREATE=$BIN/create
SUBSCRIBE=$BIN/subscribe
FAIL=0

module_unload() {
    if $verbose; then
	(killall -vv scoped || true) 2>&1 | sed -e 's/^/PREPARE: /'
    else
	(killall -vv scoped || true) >/dev/null 2> /dev/null
    fi
    if $verbose; then
	(killall -vv subevd || true) 2>&1 | sed -e 's/^/PREPARE: /'
    else
	(killall -vv subevd || true) >/dev/null 2> /dev/null
    fi
    sleep 0.2
    if mount | grep -q psfs; then
	umount /pubsub
    fi
    sleep 0.2
    if kldstat | grep -q psfs; then
	kldunload psfs
    fi
}

module_load() {
    if $verbose; then
	echo "PREPARE: Installing new kernel module version..."
	(cd $MODULE_DIR; make install) | sed -e 's/^/PREPARE: /'
	echo -n "PREPARE: " 
    else
	(cd $MODULE_DIR; make install) > /dev/null
    fi
    kldload $VERB psfs
    if kldstat -qm psfs; then :; else
	exit 1
    fi
    # sysctl debug.pubsub_debug_mask=0x0000000000020093
    mount -t psfs psfs /pubsub
}

scoped_start() {
    $SCOPED $VERB &
}

subevd_start() {
    $SUBEVD $VERB &
}

check_start() {
    if [ "X$VERBOSE" != "X" ]; then
	VERB=-v
        verbose=true
    fi 
    if [ "X$FAILFAST" != "X" ]; then
	set -e
    fi
    module_unload
    module_load
    sysctl debug.pubsub_debug_mask=0xFFFFFFFFFFFFFFFF
    # scoped_start
}

check() {
    if ! eval "$@"
    then
    	FAIL=1
    fi
}

check_end() {
    module_unload
    test_end
}

msg() {
    printf "\033[32m"
    echo $@
    printf "\033[37m"
}

vmsg() {
    [ -n "$verbose" -a "$verbose" != "false" ] && msg $@
    true;
}

# Use this at the end of check script. Otherwise 'make check' reports "passed" even if one test
# failed.
test_end() {
    exit $FAIL
}

# Set this automatically.. or move them to check_init()
if [ "X$VERBOSE" != "X" ]; then
    VERB=-v
    verbose=true
fi 

if [ "X$FAILFAST" != "X" ]; then
    set -e
fi
