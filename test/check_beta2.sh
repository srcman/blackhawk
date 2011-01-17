#!/bin/sh

#
# Test that were successfully run at the Beta2 release
#

#export FAILFAST="yes"

#. check_prepare.sh

init_state()
{
    check_start
    scoped_start
}

end_state()
{
    killall -9 scoped
    check_end
}

#
# Start tests
#

echo "Running BETA2 tests"
echo

if ! ./check_create.sh
then
    echo "BETA2: Create tests failed"
    exit 1
else
    echo
    echo "BETA2: Create tests passed"
    echo
fi


if ! ./check_publish.sh
then
    echo "BETA2: Publish tests failed"
    exit 2
else
    echo
    echo "BETA2: Publish tests passed"
    echo
fi


if ! ./check_subscribe.sh
then
    echo "BETA2: Subscribe tests failed"
    exit 3
else
    echo
    echo "BETA2: Subscribe tests passed"
    echo
fi

