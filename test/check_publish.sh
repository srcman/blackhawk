#!/bin/sh
#
# Conformance testing for the publish system call.
# 

. check_prepare.sh

check_start

echo "START: Testing publish corner basic with RID=00::00, before starting scoped."
echo "INFO:  These tests will need to be changed once we have proper P:L authentication."

# XXX: Apr 29 2009: BUG 000006: FAILS with EFAULT (14) 
# XXX: due to not supporting zero length publications.
check $PUBLISH -e 14 $VERB -r 00::00 -l 0 || true
check $PUBLISH -e  0 $VERB -r 00::00 -l 1 
check su -m operator -c '"$PUBLISH -e 13 $VERB -r 00::00 -l 1"'

echo "START: Check metadata error handling"
# XXX: May 4 2009: Not documented as a bug yet
# XXX: Shoudl fail with EMFILE in ps_obj.c:ps_obj_init_meta_kernel but doesn't
check $PUBLISH -e  0 $VERB -g $DATA/null_page -r 00::00 -l 1 || true

check_end
