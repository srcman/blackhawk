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

if debug
DEBUGFLAGS = -ggdb -DDEBUG
else
DEBUGFLAGS = 
endif

pkgpython_PYTHON = __init__.py libpsirp_py.py libpsirp_py_.py libpsirp.py ps_debug.py
pkgpyexec_LTLIBRARIES = _libpsirp_py.la
_libpsirp_py_la_SOURCES = libpsirp_wrap.c
_libpsirp_py_la_LIBADD = ../src/libpsirp.la
_libpsirp_py_la_LDFLAGS = -module -version-info $(PSIRP_MAJOR):$(PSIRP_MINOR)
_libpsirp_py_la_CFLAGS = -I../include -I/usr/local/include/python2.6 -I/usr/local/include -I../../psfs/module -I../../helpers/net $(DEBUGFLAGS)

libpsirp_wrap.c: libpsirp.i libpsirp_*.i ../../psfs/module/ps.h ../include/libpsirp.h ../src/psirp_debug.h ../../psfs/module/ps_scope.h ../../psfs/module/ps_event.h ../../helpers/netiod/psirpd_hdrs.h ../../helpers/netiod/psirpd_ipc.h
	swig -Wall -python -threads -outdir . libpsirp.i

clean-local:
	test ! -e libpsirp_wrap.c || rm -f libpsirp_wrap.c || true
	test ! -e libpsirp_py.py  || rm -f libpsirp_py.py  || true
