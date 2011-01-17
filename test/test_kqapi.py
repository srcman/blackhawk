#!/usr/local/bin/python2.6

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

from psirp.libpsirp import *

sidstr = "12::34"
ridstr = "ab::cd"

pub = create(128)
pub.pub_s(sidstr, ridstr)

spub = sub_sync_s(sidstr, ridstr)
print(spub)
print("Version count = %d" % spub.version_count)

pskq = PubSubKQueue()
pskq.register(spub, True)

spubl = pskq.listen()
print(spubl)
print(spub)
print("Version count = %d" % spub.version_count)

pskq.unregister(spub)
pskq.close()

########

pub.buffer[0]="\xff"
pub.pub_s(sidstr, ridstr)

spub2 = sub_sync_s(sidstr, ridstr)
print(spub2)
print("Version count = %d" % spub.version_count)
