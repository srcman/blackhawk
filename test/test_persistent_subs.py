#!/usr/local/bin/python2.6

#
# Copyright (C) 2010, Oy L M Ericsson Ab, NomadicLab <pubsub@nomadiclab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# Alternatively, this software may be distributed under the terms of the BSD
# license.
#
# See LICENSE and COPYING for more details.
#


# Import the library
from psirp.libpsirp import *


# Define scope and rendezvous identifiers (in hex format)
sidstr = "ab::"
ridstr = "ab::01"

MAX_PRINT_LEN = 100


# Subscription flags:
#
#     PERSISTENT: subscription doesn't go away when a publication is received
#     FUTUREONLY: do not get the current version from the RZV node
#     LOCALSUB :  do not send a subscription to the network
#                 (doesn't mean that somebody else could do a net sub)
#     NETSUB:     send a subscription even if a local publication exists
#                 (subscribe() still returns the local one first!)


# First subscribe synchronously to the publication
print("Synchronous subscribe")
spub0 = sub_sync_s(sidstr, ridstr,
                   flags=PS_FLAGS_NET_PERSISTENT|PS_FLAGS_LOCAL_NETSUB\
                       |PS_FLAGS_LOCAL_FUTUREONLY|PS_FLAGS_NET_FUTUREONLY)
spub = spub0
print("Version (%d) %s:" % (spub.version_index, spub.vridstr))
print(spub.buffer[:MAX_PRINT_LEN])

# Update saved index, since we already "processed" the first version
spub.saved_version_index = spub.version_index


# Open an event queue
pskq = PubSubKQueue()
pskq.register(spub, True)

i = 1

print("Listen to events")
try:
    while True:
        # Listen to events (publication updates)
        spubl = pskq.listen()
        for ev, spub1 in spubl:
            spub = spub1
            print("Saved version index = %d" % spub.saved_version_index)
            # Iterate through new publication versions
            for sver in spub.get_versions_since_saved_index():
                print("Version %s:" % (sver.vridstr))
                print(sver.buffer[:MAX_PRINT_LEN])
                i += 1
except Exception, e:
    # An error occurred
    print("#%02d: Exception: %s" % (i, e))
except KeyboardInterrupt, kie:
    # E.g. ^C
    print("#%02d: Interrupted" % i)

# Clean up
pskq.unregister(spub)
pskq.close()
