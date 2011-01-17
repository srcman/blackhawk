#!/bin/sh

. check_prepare.sh

SID="::"
RID1="::10"
RID2="::11"
RID3="::12"
RID4="::13"
RID5="::14"
DELAY="sleep 1"

do_check()
{
	./printscope -s $SID $1 -v -m | awk '
	BEGIN { olditems=0 }
	/^Scope/ {
	        if (olditems == 0) {
	        	olditems=$4
	                next
	    	}
	        if($4 > olditems) {
	        	print "OK"
                        exit
                } else {
                        print "FAIL"
                        exit
                }
        }'
}


check_start
scoped_start

check $DELAY
$PUBLISH -e 0 -s $SID -r $RID1 -l 1
check $DELAY

if $verbose; then
    echo "Info: Testing publication updates with EV_ADD|EV_CLEAR flags"
fi
(
    RESULT=$(do_check); 
    if [ "$RESULT" = "OK" ]; then 
	if $verbose; then
	    echo "Ok: Test succeeded"; 
	fi
    else 
	echo "Error: Test with EV_ADD|EV_CLEAR FAILED"; 
    fi 
) &

check $DELAY
check $PUBLISH -e 0 -s $SID -r $RID2 -l 1
check $DELAY
check $PUBLISH -e 0 -s $SID -r $RID3 -l 1
check $DELAY

if $verbose; then
    echo "Info: Testing publication updates with EV_ADD|EV_ONESHOT flags"
fi
(
    RESULT=$(do_check -o); 
    if [ "$RESULT" = "OK" ]; then 
	if $verbose; then
	    echo "Ok: Test succeeded"; 
	fi
    else 
	echo "Error: Test with EV_ADD|EV_ONESHOT FAILED"; 
    fi 
) &

check $DELAY
check $PUBLISH -e 0 -s $SID -r $RID4 -l 1
check $DELAY
check $PUBLISH -e 0 -s $SID -r $RID5 -l 1
check $DELAY

check_end
