#
# Copyright (C) 2009-2010, Oy L M Ericsson Ab, NomadicLab.
# All rights reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version
# 2 as published by the Free Software Foundation.
#
# Alternatively, this software may be distributed under the terms of
# the BSD license.
#
# See LICENSE and COPYING for more details.
#

if debug
DEBUGFLAGS = -ggdb -DDEBUG
endif

bin_PROGRAMS = psirptest
psirptest_SOURCES = psirptest.c
psirptest_LDFLAGS = -L../src -lpsirp
psirptest_CFLAGS = $(DEBUGFLAGS) -I../include -I../../psfs/module

check_PROGRAMS = libpsirp_id2asc libpsirp_kqueue

# Add ONLY the test programs (not helpers)!
# These are executed
TESTS = check_libpsirp_conversions.sh
#libpsirp_id2asc

# Per-program defines
libpsirp_id2asc_SOURCES = libpsirp_id2asc.c
libpsirp_id2asc_LDFLAGS = -L/usr/local/lib -lpsirp
libpsirp_id2asc_CFLAGS = $(DEBUGFLAGS) -I../include -I../../psfs/module

AM_LDFLAGS = -L../src -lpsirp
AM_CFLAGS = $(DEBUGFLAGS) -I../include -I../../psfs/module