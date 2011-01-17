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


"""Deprecated. Import psirp.libpsirp instead."""


from psirp.libpsirp_py import *
from psirp.libpsirp import *
from psirp.ps_debug import *


def psirp_py_create(len):
    return create(len)

def psirp_py_subscribe(sid, rid):
    return subscribe(sid, rid)

def psirp_py_subscribe_sync(sid, rid, timeout=None):
    return subscribe_sync(sid, rid, timeout)

def psirp_py_publish(sid, rid, pub):
    publish(sid, rid, pub)

def psirp_py_notfound(exception): # XXX
    return isinstance(exception, NotFoundError)


def psirp_py_idtoa(id):
    return idtoa(id)


def psirp_py_debug_init(level=0, colors=False):
    init(level, colors)

def psirp_py_debug_print(level, msg):
    printdbg(level, msg)

def psirp_py_debug_enter():
    enter()
