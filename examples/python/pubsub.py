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

"""PSIRP/Python \"Raw\" API Example."""
# Note that it is NOT recommended to use these API functions!
# Please use the "object-oriented" API instead.
# And if you need efficiency, use C.

from psirp.libpsirp_py import *
from select import *
import sys

PUB_LEN = 10000
SID = PSIRP_ID_LEN*'\x00'
RID = PSIRP_ID_LEN*'\xaa'

print("psirp_create():")
x = psirp_create(PUB_LEN);
print(x)
pub = x[1]

print("\npsirp_publish():")
y = psirp_publish(SID, RID, pub)
print(y)

print("\npsirp_subscribe():")
z = psirp_subscribe(SID, RID);
print(z)
pub = z[1]

print("\npsirp_pub_rid():")
rid = psirp_pub_rid(pub);
print(repr(rid))

print("\npsirp_pub_data():")
data = psirp_pub_data(pub);
print(data)

print("\npsirp_pub_data_len():")
data_len = psirp_pub_data_len(pub);
print(data_len)

print("\npsirp_pub_fd():")
fd = psirp_pub_fd(pub);
print(fd)

# print("\nListening to kevents...:")
# if float(sys.version[:3]) < 2.6:
#     print("Python 2.6 or later required")
# else:
#     pub_id = int(pub) % 2**31
#     map = {pub_id: pub}
#     kq = kqueue()
#     kq.control([kevent(fd,
#                        KQ_FILTER_VNODE,
#                        KQ_EV_ADD | KQ_EV_CLEAR,
#                        NOTE_PUBLISH | NOTE_SUBSCRIBE,
#                        0,
#                        pub_id)],
#                0, None)
#     evl = None
#     try:
#         evl = kq.control(None, 1, None)
#         print(evl);
#         if evl is not None and len(evl) > 0 and evl[0].udata in map:
#             print(map[pub_id])
#             evl = None
#     except (KeyboardInterrupt, SystemExit):
#         print(evl)
#     kq.control([kevent(fd,
#                        KQ_FILTER_VNODE,
#                        KQ_EV_DELETE)],
#                0, None)
#     kq.close()

print("\npsirp_free():")
free = psirp_free(pub);
print free
