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


# Test application for version/page-RId computation, version
# subscriptions, and the libpsirp API for Python.


from psirp.libpsirp import *
from psirp.ps_debug import *
import hashlib, random, sys, time
#import binascii


MAX_PUB_SIZE = 512000


def run_test_ver(SIDSTR, RIDSTR, PUB_SIZE, N, CREATE):
    SID = atoid(SIDSTR);
    RID = atoid(RIDSTR); 
    
    assert idtoa(SID)    == SIDSTR
    assert idtoa(RID)    == RIDSTR
    
    DATA0 = PUB_SIZE*'\x00'
    HASH0 = hashlib.sha1(DATA0).digest()
#    VRID0 = debug_compute_vrid(debug_compute_prids(DATA0))
    
    print "Publish and subscribe %d versions:" % N    
    
    p = create(PUB_SIZE)
    p.publish(SID, RID)
    time.sleep(0.3) # let scoped do its work
    p_buffer = p.buffer
    
    assert p.len         == PUB_SIZE
    assert len(p_buffer) == PUB_SIZE
    assert p.sid         == SID
    assert p.rid         == RID
#    assert p.vrid[:]     == VRID0, "%r != %r" % (p.vrid[:], VRID0)
    
    p_hash  = hashlib.sha1(p_buffer).digest();
    p_prids = debug_compute_prids(p_buffer)
#    p_vrid  = debug_compute_vrid(p_prids);
    
    assert p_hash        == HASH0
#    assert p_vrid        == VRID0

    for n in xrange(N):
        print n+1, ; sys.stdout.flush()
        
        s = p.resubscribe() # alternative: s = subscribe(SID, RID)
        s_buffer = s.buffer
        del p # p gets freed at some point
        del p_buffer
        
        assert s.len         == PUB_SIZE
        assert len(s_buffer) == PUB_SIZE
        assert s.sid         == SID
        assert s.rid         == RID
        
#        assert s.vrid[:]     == p_vrid, "%r != %r" % (s.vrid[:], p_vrid)
        
        s_hash = hashlib.sha1(s_buffer).digest()
        assert s_hash        == p_hash
        
        v = subscribe(s.rid, s.vrid)
        v_prids = v.get_prids()
        for i in xrange(len(v_prids)):
            assert v_prids[i][:] == p_prids[i]
        del v
        del v_prids
        
        if n == N-1:
            break
        
        if CREATE:
            new_size = random.randint(1, (MAX_PUB_SIZE/N)*(n+1))
            p = create(new_size)
            p_buffer = p.buffer
            assert p.len         == new_size
            assert len(p_buffer) == new_size
            p_buffer[0:min(new_size, PUB_SIZE)] = \
                s_buffer[0:min(new_size, PUB_SIZE)]
            PUB_SIZE = new_size # modifying a supposed constant is a bit ugly...
        else:
            p = s
            p_buffer = s_buffer
        del s
        del s_buffer
        
        for x in xrange(random.randint(0, PUB_SIZE)):
            i = random.randint(0, p.len-1)
            c = random.randint(0x00, 0xff)
            p_buffer[i] = chr(c)
            
        p_hash  = hashlib.sha1(p_buffer).digest();
        p_prids = debug_compute_prids(p_buffer)
#        p_vrid  = debug_compute_vrid(p_prids)
        
        if CREATE:
            p.publish(SID, RID)
        else:
            p.republish()
        time.sleep(0.1) # we don't want to get the old version when we re-sub
    print


def _main():
    import getopt
    
    prog_name = str(__file__).split("/")[-1]

    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "s:r:b:n:cv", ["--help"])
        #print opts, args
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)
    
    sidstr, ridstr, pub_size, n, create = \
        None, None, None, None, None
    SIDSTR, RIDSTR, PUB_SIZE, N, CREATE = \
        "abcd::", "abcd::aa11", 4*4096+1001, 20, False # default values
    
    for o, a in opts:
        if o == "-h" or o == "--help":
            print "Usage: %s [-s sid -r rid -b bytes -n iters -c]" % prog_name
            sys.exit()
        elif o == "-s":
            sidstr = a
        elif o == "-r":
            ridstr = a
        elif o == "-b":
            pub_size = int(a)
        elif o == "-n":
            n = int(a)
        elif o == "-c":
            create = True
        elif o == "-v":
            pass
        else:
            assert False, "Unhandled option: %r" % o
    
    if sidstr is None:
        print "%s: Using default SId: %s" % (prog_name, SIDSTR)
        sidstr = SIDSTR
    if ridstr is None:
        print "%s: Using default RId: %s" % (prog_name, RIDSTR)
        ridstr = RIDSTR
    if pub_size is None:
        print "%s: Using default initial publication size: %d" \
            % (prog_name, PUB_SIZE)
        pub_size = PUB_SIZE
    if n is None:
        print "%s: Using default iteration count: %s" % (prog_name, N)
        n = N
    if create is None:
        create = CREATE

    run_test_ver(sidstr, ridstr, pub_size, n, create)

if __name__ == "__main__":
    _main()
