#!/bin/sh

if [ "$1" = "-h" ] || [ "$1" = "--help" ]
then
    echo $0 removes various files that \'make clean distclean\' leaves behind
    exit
fi

set -x

rm -f aclocal.m4
rm -rf autom4te.cache
rm -f config.guess
rm -f config.h.in
rm -f config.sub
rm -f configure
rm -f depcomp
rm -f INSTALL
rm -f install-sh
rm -f ltmain.sh
rm -f missing
rm -f NEWS
rm -f py-compile

rm -f m4/libtool.m4
rm -f m4/lt*.m4

rm -rf psfs/module/@
rm -rf psfs/module/machine

find . -type f -name 'Makefile.in' -exec rm -fv '{}' \;
