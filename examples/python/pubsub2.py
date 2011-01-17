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


"""PSIRP/Python Object-Oriented API Example."""
# This example demonstrates various basic API features.
#
# However, it's not necessarily intended to be an example of good and
# clean programming practices.


from psirp.libpsirp import *
import sys, time


PUB_LEN = 10000
SID     = PSIRP_ID_LEN*'\x00' # Binary SId example ("Scope 0")
RIDSTR  = "aa::bb"            # Hex-string RId example

# Conversions
SIDSTR  = idtoa(SID)
RID     = atoid(RIDSTR)


print("create():")
pub = create(PUB_LEN);
print(pub)

print("\npublish()")
pub.publish(SID, RID)

time.sleep(0.25) # Let scoped create the scope and add the RId

print("\nsubscribe():")
spub = sub_s(SIDSTR, RIDSTR); # Subscribe with hex-string Ids
print(spub)

print("\nbuffer:")
buf = spub.buffer
print(repr(buf))
print("buffer data:")
buf = spub.buffer
print("%r ..." % buf[0:10])

print("\nsid:")
sid = spub.sid
print(repr(sid[:]))
print("rid:")
rid = spub.rid
print(repr(rid[:]))
print("vrid:")
vrid = spub.vrid
print(repr(vrid[:]))

print("\nrepublish and resubscribe:")
buf[0:10] = '0123456789' # Modify spub's buffer
spub.republish()
spub2 = pub.resubscribe()
print("%r ..." % spub2.buffer[0:10])

print("\ndel")
del spub # The GC unmaps the publication from our memory space at some point
