#!/usr/local/bin/bash

if [ -z $1 ] && [ -z $2 ]
then
echo "Usage: $0 <start RId> <end RId>"
exit 0
fi

for (( i = $1; i < $2; i++ ))
do
    len=`echo $i | wc -c`
    VAR=$i

    for (( j = len; j <= 64; j++ ))
    do
	VAR="0${VAR}"
    done
    echo "Step $i"
    psirptest -s -r $VAR
done
