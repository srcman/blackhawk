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

PSIRP_MAJOR = 0
PSIRP_MINOR = 3

if debug
DEBUGFLAGS = -ggdb -DDEBUG
endif

lib_LTLIBRARIES = libpsirp.la
libpsirp_la_LDFLAGS = -version-info $(PSIRP_MAJOR):$(PSIRP_MINOR)
libpsirp_la_CFLAGS = $(DEBUGFLAGS) -I../include -I../../psfs/module -Werror
libpsirp_la_SOURCES = libpsirp.c psirp_debug.c psirpkq.c

include_HEADERS = ../include/libpsirp.h
