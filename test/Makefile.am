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

sbin_PROGRAMS  = create publish subscribe subevents printscope pubandsub

create_SOURCES = create.c libmodule.c
publish_SOURCES = publish.c libmodule.c
subscribe_SOURCES = subscribe.c
subevents_SOURCES = subevents.c
printscope_SOURCES = printscope.c
pubandsub_SOURCES = pubandsub.c

TESTS = check_create.sh check_publish.sh check_subscribe.sh \
        check_bug_000008.sh check_bug_000009.sh check_bug_000010.sh \
	check_versions.sh

if debug
DEBUGCFLAGS =-ggdb -DDEBUG
else
DEBUGCFLAGS =
endif

INCLUDES  = -I$(srcdir) -I../libpsirp/include -I../psfs/module 
INCLUDES  += -I/usr/local/include

AM_CFLAGS  = -Werror -Wall -DHAVE_CONFIG_H 
AM_CFLAGS += $(INCLUDES) $(DEBUGCFLAGS)

AM_LDFLAGS = -L../libpsirp/src -lcrypto -lpsirp
