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

# Packet receiver utility
# -----------------------
#
# Do note that this is a FreeBSD version that requires that the
# libpsirp API for Python is compiled with socket support enabled and
# that the psfs kernel module is loaded.


from psirp.libpsirp_py import *
import time


iface = "em1"
n = 10
verbose=False


def main():
    sockdata = psirp_py_sock_create(iface)
    sock = sockdata.sock
    try:
        print("Receiving (n = %d, iface=%s)..." % (n, iface))
        while True:
            t1 = time.time()
            for i in xrange(n):
                data = psirp_py_sock_recv(sockdata, 1500)
            if (verbose):
                print("Received %d bytes" % data[0])
            t2 = time.time()
            print("Received: %f bytes/s" % ((n*1500)/(t2-t1)))
            
    except (KeyboardInterrupt, SystemExit):
        pass
    psirp_py_sock_close(sockdata)

if __name__ == "__main__":
    main()
