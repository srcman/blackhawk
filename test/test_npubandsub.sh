#!/usr/bin/env bash

PSIRP_SID_LEN=64
PSIRP_RID_LEN=64

if [ -z $1 ] && [ -z $2 ] && [ -z $3 ] && [ -z $4 ]
then
    echo "Usage: $0 <start SId> <end SId> <start RId> <end RId>"
    exit 0
fi

ISID=$1
ESID=$2
IRID=$3
ERID=$4

for (( i = $ISID; i <= $ESID; i++ ))
do
    SID_LEN=`echo $i | wc -c`
    SID=$i

    for (( m = $SID_LEN; m <= $PSIRP_SID_LEN; m++ ))
    do
	SID="0${SID}"
    done
    echo "Scope step $i" 
#    mkdir /pubsub/$SID
    
    for (( j = $IRID; j <= $ERID; j++ ))
    do
	RID_LEN=`echo $j | wc -c`
	RID=$j

	for (( n = $RID_LEN; n <= $PSIRP_RID_LEN; n++ ))
	do
	    RID="0${RID}"
	done
	echo "RId step $j" 
	./pubandsub -s $SID -r $RID -v || break
    done
    
done
