#!/bin/sh
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

# If BSD kernel has not been compiled, these will be missing. Fix it.

if [ -f /usr/src/sys/sys/vnode_if.h ]; then
   :
else
   if id -u | grep -q '^0$'; then
      awk -f /usr/src/sys/tools/vnode_if.awk /usr/src/sys/kern/vnode_if.src -hpq
      mv vnode_if.h /usr/src/sys/sys
      mv vnode_if_newproto.h /usr/src/sys/sys
      mv vnode_if_typedef.h /usr/src/sys/sys
   else
      echo "You need root privileges to fix the kernel sources."
      exit 1
   fi
fi

# for some reason BSD version of autoreconf doesn't automagically create these
touch NEWS 
autoreconf -i || echo "Trying again..." && autoreconf -i
./configure --enable-debug $@
#./configure $@
