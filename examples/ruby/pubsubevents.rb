#!/usr/bin/env ruby


require 'libpsirp_rb'


# Create IDs
ID_LEN = Libpsirp_rb::PSIRP_ID_LEN
id0 = "\x00"*ID_LEN
sid1 = id0.clone; sid1[0] = "\xaa"         # aa::
id1 = id0.clone; id1[ID_LEN-2] = "\x10"    # ::1000
rid1 = id1.clone; rid1[ID_LEN-1] = "\x01"  # ::1001
rid2 = id1.clone; rid2[ID_LEN-1] = "\x02"  # ::1002
rid3 = id1.clone; rid3[ID_LEN-1] = "\x03"  # ::1003
#rid4 = id1.clone; rid4[ID_LEN-1] = "\x04"  # ::1004
rid4 = Libpsirp_rb.psirp_rb_atoid("::1004") # handy alternative


# Publish test data
Libpsirp_rb.psirp_rb_publish_string(sid1, rid1, "0123456789")
sleep 0.2 # scope is created and publication is added to it
Libpsirp_rb.psirp_rb_publish_string(sid1, rid2, "abcdef")
sleep 0.1
Libpsirp_rb.psirp_rb_publish_string(sid1, rid3, "\xa5"*5000)
sleep 0.1


# Subscribe to data
spub1 = Libpsirp_rb.psirp_subscribe(sid1, rid1)[1]
spub2 = Libpsirp_rb.psirp_subscribe(sid1, rid2)[1]
spub3 = Libpsirp_rb.psirp_subscribe(sid1, rid3)[1]
spubs = Libpsirp_rb.psirp_subscribe(sid1, sid1)[1] # scope
#spub4 = Libpsirp_rb.psirp_rb_subscribe_sync(sid1, rid4, nil)

spub_list = [spub1, spub2, spub3, spubs]

print "Publications (pub, fd, len):\n"
for spub in spub_list do
    print spub.inspect, " "
    print Libpsirp_rb.psirp_pub_fd(spub), " "
    print Libpsirp_rb.psirp_pub_data_len(spub), "\n"
end


# Create kqueue
kq = Libpsirp_rb.psirp_rb_kqueue()

# Register to events
for spub in spub_list do
    Libpsirp_rb.psirp_rb_kevent_register(kq, spub)
end


N=50; T_S=0
# Get N events and quit loop
print "Listening for ", N, " events. Press ^C to quit.\n"
print "Do not unload the kernel module before quitting!\n"
N.times do
  # Listen
  # (timeout: nil = wait forever, 0 = return immediately, 1200 = wait 1.2 s;
  # multithreaded Ruby applications should use 0, because otherwise
  # _all_ threads will pause execution while one is listening!)
  spub = Libpsirp_rb.psirp_rb_kevent_listen(kq, nil)
  
  # Note that the underlying publication version has been changed (and
  # unmapped from our memory space), so we don't have to re-subscribe
  # or free anything!
  sbuf = Libpsirp_rb.psirp_rb_pub_to_string(spub)
  
  print "Publication (pub, fd, len, ver):\n"
  print spub.inspect, " "
  print Libpsirp_rb.psirp_pub_fd(spub), " "
  print sbuf.length, " "
  version_index = Libpsirp_rb.psirp_pub_current_version_index(spub)
  version_count = Libpsirp_rb.psirp_pub_version_count(spub)
  print version_index+1, "/", version_count, "\n"
  vrid_list = Libpsirp_rb.psirp_rb_pub_get_vrids(spub)
  print "Versions:\n"
  for vrid in vrid_list:
      print Libpsirp_rb.psirp_idtoa(vrid), "\n"
  end
  
  if T_S > 0
    print "Sleeping ", T_S, " s...\n"
    sleep T_S
    print "Woke up!\n"
  end
  
  # We can also unregister. Here we do that if the event was for our
  # scope, just as an example.
  if spub_list.include? spubs and
      Libpsirp_rb.psirp_pub_fd(spub) == Libpsirp_rb.psirp_pub_fd(spubs)
    print "Scope event\n"
    # First we can print the RIds in the scope
    rid_list = Libpsirp_rb.psirp_rb_scope_get_rids(spub)
    print "RIds in scope:\n"
    for rid in rid_list:
        print Libpsirp_rb.psirp_idtoa(rid), "\n"
    end

    print "Unsubscribe from the scope\n"
    Libpsirp_rb.psirp_rb_kevent_unregister(kq, spub)
    Libpsirp_rb.psirp_free(spub)
    spub_list.delete(spubs)
    
    # Subscribe to rid4 instead
    print "Subscribe to ", Libpsirp_rb.psirp_idtoa(rid4), " instead\n"
    spub4 = Libpsirp_rb.psirp_subscribe(sid1, rid4)[1]
    spub_list.push(spub4)
    Libpsirp_rb.psirp_rb_kevent_register(kq, spub4)
  end
end


# Close kqueue
Libpsirp_rb.psirp_rb_kqueue_close(kq)


# Examples:
#
# # Re-publish:
# psirptest -p -f /COPYRIGHT -c aa:: -r ::1001
# => #<SWIG::TYPE_p_void:0x800e44668> 6 6197 2/2
#
# # New publication in scope:
# psirptest -p -f /COPYRIGHT -c aa:: -r ::1004
# => #<SWIG::TYPE_p_void:0x800e44690> 9 4096 4/4
