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

sbin_PROGRAMS  = scoped

scoped_SOURCES = scoped.c

if debug
DEBUGCFLAGS =-ggdb -DDEBUG
else
DEBUGCFLAGS =
endif

INCLUDES  = -I$(srcdir) -I../../libpsirp/include -I../module 
#INCLUDES  += -I/usr/local/include

AM_CFLAGS  = -Werror -Wall -DHAVE_CONFIG_H 
AM_CFLAGS += $(INCLUDES) $(DEBUGCFLAGS)

AM_LDFLAGS  = -L../../libpsirp/src -lpsirp
AM_LDFLAGS += -lz

include_HEADERS = ../module/ps.h ../module/ps_scope.h ../module/ps_syscall.h ../module/ps_magic.h
