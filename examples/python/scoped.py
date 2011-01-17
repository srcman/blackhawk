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


"""Scope Daemon Example Implementation for Blackhawk v0.1. Might be obsolete."""


from psirp.libpsirp_py_ import *
import errno, select, struct, sys


# Constants
ROOT_SID = PSIRP_ID_LEN*'\x00'
PAGE_SIZE = 4096
INT_SIZE = 4
SDP_COUNT_OFFSET = PSIRP_ID_LEN 
SDP_ENTRIES_OFFSET = SDP_COUNT_OFFSET+INT_SIZE
PEP_COUNT_OFFSET = PSIRP_ID_LEN+1
PEP_EVENTS_OFFSET = PEP_COUNT_OFFSET+2+(PSIRP_ID_LEN*2-(PEP_COUNT_OFFSET+2))


def scope_set_count(data, count):
    """Sets the RId count for a scope."""
    
    # Set data at index i
    i = SDP_COUNT_OFFSET
    data[i:i+INT_SIZE] = struct.pack('i', count)

def scope_set_rid(data, index, rid):
    """Sets the RId at the given index."""
    
    # Set data at index i
    i = SDP_ENTRIES_OFFSET + index*PSIRP_ID_LEN
    data[i:i+PSIRP_ID_LEN] = rid

def scope_get_rids(data):
    """Returns the RIds in a scope as a list."""
    
    # Get count
    i = SDP_COUNT_OFFSET
    count = struct.unpack("i", data[i:i+INT_SIZE])[0]
    
    rids = {}
    
    for index in xrange(count):
        # Get the RId at index and add it to the dictionary
        i = SDP_ENTRIES_OFFSET + index*PSIRP_ID_LEN
        rid = buffer(data[i:i+PSIRP_ID_LEN])
        rids[rid] = None
    
    return rids

def pep_get_sidrids(pep_file):
    """Returns the SId/RIds pairs in an event file."""
    
    pep_file.seek(0)
    data = pep_file.read()
    
    # Get count
    i = PEP_COUNT_OFFSET
    count = struct.unpack("B", data[i:i+1])[0]
    
    sidrids = []
    
    for index in xrange(count):
        # Get the SId/RId pair at index and add it to the list
        i1 = PEP_EVENTS_OFFSET + index*PSIRP_ID_LEN*2
        i2 = i1 + PSIRP_ID_LEN
        i3 = i2 + PSIRP_ID_LEN
        sid = buffer(data[i1:i2])
        rid = buffer(data[i2:i3])
        sidrids.append((sid, rid))
    
    return sidrids


def scope_create(scope_sid, scope_rid, initial_rid):
    """Creates a new scope."""
    
    print("scope_create: %s/%s" \
              % (psirp_idtoa(scope_sid), psirp_idstoa(scope_rid, initial_rid)))

    # Create publication
    pub = psirp_py_create(PAGE_SIZE)
    data = pub.buffer
    
    # Set magic value and publication type (in C)
    psirp_py_scope_init(pub.pub)
    count = 0
    
    # Add scope RId
    scope_set_rid(data, count, scope_rid)
    count += 1
    
    # Add initial RId
    if (scope_rid != initial_rid):
        scope_set_rid(data, count, initial_rid)
        count += 1
    
    # Set RId count
    scope_set_count(data, count)
    
    # Publish new scope
    psirp_py_publish(scope_sid, scope_rid, pub)

def scope_add_rid(scope_sid, scope_rid, added_rid, pub):
    """Adds a RId to a scope."""
    
    print("scope_add_rid: %s/%s" \
              % (psirp_idtoa(scope_sid), psirp_idstoa(scope_rid, added_rid)))
    
    # Get RIds in scope
    data = pub.buffer
    rids = scope_get_rids(data)
    count = len(rids)
    
    # Check if the RId is already in this scope
    if added_rid in rids:
        return errno.EALREADY
    
    # Add RId to this scope
    scope_set_rid(data, count, added_rid)
    count += 1
    
    # Update RId count
    scope_set_count(data, count)
    
    # Re-publish scope
    psirp_py_publish(scope_sid, scope_rid, pub)

def scope_add(scope_sid, scope_rid, rid):
    """Adds publications to scopes and creates new scopes."""
    
    try:
        # Subscribe to the scope
        pub = psirp_py_subscribe(scope_sid, scope_rid)
    except:
        # Scope not found. Need to create a new scope and add this publication.
        return scope_create(scope_sid, scope_rid, rid);
    
    # Scope found. Add this publication to it.
    return scope_add_rid(scope_sid, scope_rid, rid, pub)


def _main():
    # Bootstrap by adding the root SId
    scope_add(ROOT_SID, ROOT_SID, ROOT_SID)
    
    # Open the events file and get its descriptor
    # (Note: This file is only read by scoped, not normal appications.)
    pubs_file = open("/pubsub/pubs")
    fd = pubs_file.fileno()
    
    # Register to events
    kq = select.kqueue()
    evf = select.kevent(fd,                     # ident
                        select.KQ_FILTER_VNODE, # filter
                        select.KQ_EV_ADD
                        | select.KQ_EV_CLEAR,   # flags
                        NOTE_PUBLISH,           # fflags
                        0,                      # data
                        0)                      # udata
    kq.control([evf], 0, None) # changelist, max_events, timeout
    
    # Listen to events
    while True:
        evl = kq.control(None, 1, None)
        
        if evl is not None:
            # Read events (SId/RId pairs)
            pub_evs = pep_get_sidrids(pubs_file)
            
            # Add scopes and/or publications
            for sid, rid in pub_evs:
                scope_add(ROOT_SID, sid, rid)

if __name__ == "__main__":
    _main()
