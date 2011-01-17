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

#SUBDIRS = test

sbin_PROGRAMS  = netiod
netiod_SOURCES = netiod.c \
		psirpd_config.c \
		psirpd_packet.c \
		psirpd_net.c \
		psirpd_sec_pla.c \
		psirpd_fwd_bf.c \
		psirpd_rzv.c \
		psirpd_out_q.c \
		psirpd_hdrs.c \
		psirpd_ipc.c

if debug
DEBUGCFLAGS =-ggdb -DDEBUG
else
DEBUGCFLAGS =
endif

INCLUDES  = -I$(srcdir)
INCLUDES  += -I../../psfs/module
INCLUDES  += -I../../libpsirp/include
INCLUDES  += -I../../libpsirp/src
INCLUDES  += -I/usr/local/include

AM_CFLAGS  = -Werror -Wall -DHAVE_CONFIG_H
AM_CFLAGS += $(INCLUDES) $(DEBUGCFLAGS)
#AM_CFLAGS += -save-temps # XXX

AM_LDFLAGS = -L../../psfs/module
AM_LDFLAGS += -L../../libpsirp/src
AM_LDFLAGS += -L/usr/local/lib
AM_LDFLAGS += -lpsirp

install-exec-hook:
	test -f /etc/netiod.conf || cp -p netiod.conf /etc/