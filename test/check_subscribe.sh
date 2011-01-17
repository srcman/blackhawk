#!/bin/sh
#
# Conformance testing for the subscribe system call.
# 
TMPFILE="/tmp/_sub_test.$$"
SRCFILE="/COPYRIGHT"
DELAY="sleep 1"

exit_if_data_exists() {
    if [ -s "$1" ]; then
        msg "Fail: $1 contains data while it should not"
	if [ -s "$FAILFAST" ]; then
		check_end
	        exit 1
	else
		return 1
	fi
    fi
    return 0
}

exit_if_data_differs() {
    if ! diff $1 $2 >/dev/null; then
        msg "Fail: $1 and $2 differ"
	if [ -s "FAILFAST" ]; then
		check_end
		exit 1
	else
		return 1
	fi
    fi
    return 0
}

. check_prepare.sh

check_start
scoped_start
sleep 1

msg "Checking subscribe system call"

msg "Scope 0 checks"
check $PUBLISH -e  0 $VERB -r ::10 -f $SRCFILE
check $SUBSCRIBE -e  2 $VERB -r ::08 -f $TMPFILE 
exit_if_data_exists $TMPFILE
rm $TMPFILE

check $SUBSCRIBE -e  0 $VERB -r ::10 -f $TMPFILE 
exit_if_data_differs $SRCFILE $TMPFILE
rm $TMPFILE

check $SUBSCRIBE -e  0 $VERB -r :: 


vmsg ""
msg "Subscribing in non-existent scopes"
check $SUBSCRIBE -e  3 $VERB -s ::50 -r ::90 
check $SUBSCRIBE -e  3 $VERB -s ::80 -r ::80 


vmsg ""
msg "Subscribing in valid scope"
check $PUBLISH -e  0 $VERB -s ::2000 -r ::1000 -f $SRCFILE
check $SUBSCRIBE -e  2 $VERB -s ::2000 -r ::1100 
check $SUBSCRIBE -e  0 $VERB -s ::2000 -r ::1000 -f $TMPFILE 
exit_if_data_differs $SRCFILE $TMPFILE
rm $TMPFILE

vmsg ""
msg "Testing synchronized subscribe"
RESFILE="/tmp/_res.$$"
echo "UNKNOWN" >$RESFILE

(
    check $SUBSCRIBE -e  0 $VERB -z -s ::100000 -r ::CAFE00 -f $TMPFILE
    if ! exit_if_data_differs $SRCFILE $TMPFILE; then
    	echo "FAIL" >$RESFILE
    fi
    rm $TMPFILE
    echo "OK" >$RESFILE
) &

check $DELAY; check $DELAY
check $PUBLISH -e  0 $VERB -s ::100000 -r ::ABBA00 -f $SRCFILE
check $PUBLISH -e  0 $VERB -s ::100000 -r ::CAFE00 -f $SRCFILE
check $DELAY

RES=$(head -1 $RESFILE)
if [ "x$RES" != "xOK" ]; then
    msg "Fail: Synchronized subscribe failed"
    ps -ww | awk '/subscribe/ && !/ awk/ {print $1}' | xargs kill -9
    $DELAY
else
    vmsg "OK: Synchronized subscribe succeeded"
    rm $RESFILE
fi

check_end
