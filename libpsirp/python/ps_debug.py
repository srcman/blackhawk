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


from psirp import libpsirp_py
import sys
import hashlib


# Constants

PSIRP_PY_DEBUG = 1 # XXX

from libpsirp_py import PSIRP_DBG_NONE, PSIRP_DBG_ERR, PSIRP_DBG_WARN,  \
    PSIRP_DBG_INFO, PSIRP_DBG_FNCE, PSIRP_DBG_TIMER, PSIRP_DBG_HEXDUMP, \
    PSIRP_DBG_GARB, PSIRP_DBG_MEMORY


# Debugging functions

def debug_init(level=0, colors=False):
    if PSIRP_PY_DEBUG:
        libpsirp_py.psirp_debug_init_print(level, 0)
        if colors:
            libpsirp_py.psirp_debug_printcols()

def debug_print(level, msg, *args):
    if PSIRP_PY_DEBUG:
        frame = sys._getframe(1) # caller's frame
        libpsirp_py.psirp_py_debug_print_(level,
                                          frame.f_code.co_filename,
                                          frame.f_code.co_name,
                                          (msg % args))
def debug_enter():
    if PSIRP_PY_DEBUG:
        frame = sys._getframe(1) # caller's frame    
        libpsirp_py.psirp_py_debug_enter_(frame.f_code.co_filename,
                                          frame.f_code.co_name,
                                          frame.f_lineno)

def debug_return(retval=None):
    # Hmm, could we use some continuation tricks here to emulate a
    # real return...? ;)
    if PSIRP_PY_DEBUG:
        frame = sys._getframe(1) # caller's frame
        return libpsirp_py.psirp_py_debug_return_(frame.f_code.co_filename,
                                                  frame.f_code.co_name,
                                                  frame.f_lineno,
                                                  retval)
    return retval


# Page- and version-RId computation functions
# (should be formed in the same way as in the kernel)

def debug_compute_prids(data):
    PRID_PREFIX = "Page\x00\x00\x00\x00\x00\x00\x00\x00"
    PAGE_SIZE = 4096
    
    prids = []
    for i in xrange((len(data)-1)/PAGE_SIZE + 1):
        offset = i*PAGE_SIZE
        hash = hashlib.sha1(data[offset:offset+PAGE_SIZE]).digest()
        prid = PRID_PREFIX + hash
        prids.append(prid)
    return prids

# XXX: The algorithm below is not anymore compatible with the one used
#      in the kernel.
# def debug_compute_vrid(prids):
#     VRID_PREFIX = "Version\x00\x00\x00\x00\x00"
#     
#     h = hashlib.sha1()
#     for prid in prids:
#         h.update(prid)
#     hash = h.digest()
#     vrid = VRID_PREFIX + hash
#     return vrid
