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

# Note that Automake cannot be used for building kernel modules.

KMOD=psfs
SRCS=psfs_vfsops.c psfs_vnops.c ps_syscall.c psfs_subr.c ps_map.c \
     ps_socket.c ps_pit.c ps_scope.c ps_obj.c ps_pubi.c psfs_dir.c \
     ps_magic.c ps_event.c ps_debug.c
DEBUG_FLAGS=-g -DDEBUG
#DEBUG_FLAGS=
CFLAGS+=-I@/amd64/compile/PSIRP -Werror
#CFLAGS+=-save-temps # XXX

.include <bsd.kmod.mk>


uninstall:
	test ! -f ${KMODDIR}/${PROG} || rm -f ${KMODDIR}/${PROG} \
	&& echo ${PROG} uninstalled from ${KMODDIR} but might still be loaded
	test ! -f ${KMODDIR}/${PROG}.symbols || rm -f ${KMODDIR}/${PROG}.symbols
	test ! -f ${KMODDIR}/${PROG}.debug || rm -f ${KMODDIR}/${PROG}.debug
	kldxref ${KMODDIR}

distclean:
	rm -f ./${PROG} ./${PROG}.symbols ./${PROG}.debug

maintainer-clean:
	rm -f ./${PROG} ./${PROG}.symbols ./${PROG}.debug

mostlyclean:
	rm -f *.o
	rm -f ./${PROG} ./${PROG}.symbols ./${PROG}.debug

check:


info:

dvi:

ps:

pdf:

html:

install-data:

install-dvi:

install-exec:

install-html:

install-info:

install-pdf:

install-ps:

installdirs:

installcheck:


tags:
