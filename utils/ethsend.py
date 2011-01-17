#!/usr/bin/env python2.6

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

# Packet generator utility
# ------------------------
#
# Do note that the FreeBSD version requires that the libpsirp API for
# Python is compiled with socket support enabled and that the psfs
# kernel module is loaded.


import socket, struct, sys, time, traceback
import binascii


PLATFORM_LINUX   = 0
PLATFORM_FREEBSD = 1

def detect_platform():
    if sys.platform.startswith("linux2"):
        return PLATFORM_LINUX
    elif sys.platform.startswith("freebsd"):
        return PLATFORM_FREEBSD
    else:
        assert False, "Platform not supported: %r" % sys.platform
platform = detect_platform()

if platform == PLATFORM_FREEBSD:
    from psirp.libpsirp_py import *


ETH_PS_PROTO = 0xACDC # our ethertype
ETH_DATA_LEN = 1500  # max eth data size
ETH_HDR_LEN = 14 # eth header size
ETH_BC_ADDR = 6*"\xff" # eth broadcast
#AF_LINK = 18


def send_frames(if_name, max_frames=1, send_interval=0,
                verbose=False):
    if platform == PLATFORM_FREEBSD:
        frame_len = ETH_DATA_LEN
    elif platform == PLATFORM_LINUX:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                   ETH_PS_PROTO)
        frame_len = ETH_HDR_LEN + ETH_DATA_LEN
    
    frame = bytearray(frame_len)
    
    try:
        if platform == PLATFORM_FREEBSD:
            sockdata = psirp_py_sock_create(if_name)
            data_offset = 0
        elif platform == PLATFORM_LINUX:
            raw_socket.bind((if_name, ETH_PS_PROTO))
            sockaddr = raw_socket.getsockname()
            hw_addr = sockaddr[4]
            
            # Fill eth header
            struct.pack_into("!6s6sH", frame, 0,
                             ETH_BC_ADDR, hw_addr, ETH_PS_PROTO)
            
            data_offset = ETH_HDR_LEN
        
        # Fill fwd header
        # (Fwd hdr type, RZV pub data type, TTL, d, proto ver, reserved, FId,
        #  RZV pub data type again)
        fid = binascii.unhexlify("00aa000000000000000000000000000000000000000000000000000000000000")
        struct.pack_into("BBBBB5s32sBB", frame, data_offset,
                         0x01, 0x04, 255, 0, 1, 5*b'\x00', fid,
                         0x04, 0x00)
        
        for i in xrange(max_frames):
            try:
                if platform == PLATFORM_FREEBSD:
                    psirp_py_sock_send(sockdata, frame)
                elif platform == PLATFORM_LINUX:
                    raw_socket.send(frame)
                
                if verbose:
                    print "sent frame: %d" % i
            except Exception, e:
                traceback.print_exc()
                    
            if send_interval != 0 and i < (max_frames-1):
                time.sleep(send_interval)
    finally:
        if platform == PLATFORM_FREEBSD:
            psirp_py_sock_close(sockdata)
        if platform == PLATFORM_LINUX:
            raw_socket.close()


def main():
    import getopt
    
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "i:c:t:hv", ["help"])
        #print opts, args
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)
    
    if_name, kwargs = None, {}
    for o, a in opts:
        if o in ("-h", "--help"):
            print str(__file__), "-i interface [-c count -t interval -v]"
            sys.exit()
        elif o == "-i":
            if_name = a
        elif o == "-c":
            kwargs["max_frames"] = int(a)
        elif o == "-t":
            kwargs["send_interval"] = float(a)
        elif o == "-v":
            kwargs["verbose"] = True
        else:
            assert False, "Unhandled option: %r" % o
    
    assert if_name is not None, "interface name is mandatory (-i interface)"
    
    send_frames(if_name, **kwargs)
        
if __name__ == "__main__":
#    print str(__file__), "started as __main__"
    main()
#    print str(__file__), "stopped"
