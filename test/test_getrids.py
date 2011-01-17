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

print("Create publication")
p = create(4097)
print("Publish publication")
p.pub_s("12::34", "56::78")
p.pub_s("12::34", "56::79")
p.pub_s("12::34", "56::7a")

print("Subscribe to scope")
s = subscribe_sync(p.sid, p.sid)
print("Scope: SIds")
for sid in s.get_rids():
    print idtoa(sid[:])
print("Scope: Version-RIds")
for vrid in s.get_vrids():
    print idtoa(vrid[:])

print("Subscribe to publication version")
pv = subscribe(p.rid, p.vrid)
print("Publication: Page-RIds")
for prid in pv.get_prids():
    print idtoa(prid[:])
