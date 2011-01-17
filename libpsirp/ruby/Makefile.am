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


BUILT_SOURCES = libpsirp_wrap.c

PSIRP_MAJOR = 0
PSIRP_MINOR = 3

FBSD_VER = `uname -r | grep -o '^[7-9]'`

if debug
DEBUGFLAGS = -ggdb -DDEBUG
else
DEBUGFLAGS = 
endif

libpsirp_rbdir = $(libdir)/ruby/site_ruby/1.8/amd64-freebsd$(FBSD_VER)

libpsirp_rb_LTLIBRARIES = libpsirp_rb.la
libpsirp_rb_la_SOURCES = libpsirp_wrap.c
libpsirp_rb_la_LIBADD = ../src/libpsirp.la
libpsirp_rb_la_LDFLAGS = -version-info $(PSIRP_MAJOR):$(PSIRP_MINOR)
libpsirp_rb_la_CFLAGS = -I../include -I/usr/local/lib/ruby/1.8/amd64-freebsd$(FBSD_VER)/ -I../../psfs/module -I/usr/local/include $(DEBUGFLAGS)

libpsirp_wrap.c: libpsirp.i libpsirp_*.i ../../psfs/module/ps.h ../include/libpsirp.h
	swig -Wall -ruby -outdir . libpsirp.i

clean-local:
	test ! -e libpsirp_wrap.c || rm -f libpsirp_wrap.c || true
