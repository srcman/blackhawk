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

"""PSIRP Local Area Intradomain Rendezvous Daemon."""
# XXX: Warning: Contains quite many hackz and some copy-pasted code fragments.
#      A well-defined state model would be nice to have.
#      Understanding all different scenarios and their sub-cases can be
#      really painful! You've been warned.


from psirp.libpsirp import *
from psirp.ps_debug import *
#import psirp.libpsirp_py # XXX

import array, errno, select, signal, sys, re, time, traceback
#import pdb # debugger, add breakpoint: pdb.set_trace()


# Static identifiers
ROOT_SCOPE_SID        = buffer(PSIRP_ID_LEN*'\x00')
DEFAULT_IPC_SID       = atoid("acdc::")
DEFAULT_IPC_LOCAL_RID = atoid("acdc10::")
DEFAULT_IPC_NET_RID   = atoid("acdc20::")
EMPTY_RID             = buffer(PSIRP_ID_LEN*'\x00')
EMPTY_FID             = buffer(PSIRP_FID_LEN*'\x00')
#FULL_FID              = buffer(PSIRP_FID_LEN*'\xff')

# Everything else except "::" (Scope 0) and DEFAULT_IPC_SID
# are network scopes:
DEFAULT_LOCAL_SID_PATTERN = "(?!^(::|"+idtoa(DEFAULT_IPC_SID)+")$)"

# Pub/sub networking configuration file
CONFIG_FILE_NAME = "/etc/netiod.conf"

# Timer kevent/kqueue ident used for signaling exceptions across threads
TIMER_IDENT  = 0x7fffffff


class Subscriber(object):
    """Subscriber for various rendezvous-related events."""
    
    class Subs(object):
        """Local subscribes."""
        
        def __init__(self, parent):
            self.parent = parent # Subscriber
            self.net_subs = SIdRIdDict()
            self.data_subs = SIdRIdVRIdCountDict()
        
        class SubsPub(Publication):
            """Pseudo-publication for getting events from the subs file."""
            
            def __init__(self, subs_file, parent):
                super(type(self), self).__init__(None) # XXX
                
                self.subs_file = subs_file
                self.pep = libpsirp_py.ps_event_page()
                self.parent = parent
            
            def __del__(self):
                try:
                    self.subs_file.close()
                except:
                    pass
            
            @property
            def fd(self):
                return self.subs_file.fileno()
            
            def read(self):
                return libpsirp_py.psirp_py_read_event_page(self.fd, self.pep)
            
            def handle_event(self, event, pub):
                debug_enter()
                
                subs = pub.read() # This "publication" actually wraps a file
                debug_print(PSIRP_DBG_GARB, "%d subscriptions", len(subs))
                
                for sid, rid, flags in subs:
                    if flags & PS_FLAGS_LOCAL_LOCALSUB:
                        # XXXXX: Not reliable. Somebody else
                        #        might make a network subscription.
                        #        Also note that this flags overrides
                        #        all others (such as e.g. NETSUB)
                        debug_print(PSIRP_DBG_GARB,
                                    "Sub ignored "
                                    "(local only: SId/RId: %s (0x%04x)",
                                    idstoa_d(sid, rid), flags)
                        continue # for sid, rid in subs
                    
                    # Make copies, beacause data in the underlying
                    # page can change (or become invalid)
                    sid, rid = copybuf(sid), copybuf(rid)
                    sid_str = idtoa(sid)
                    sidrid_str_d = idstoa_d(sid, rid)
                    
                    debug_print(PSIRP_DBG_GARB,
                                "Subscription to SId/RId: %s (0x%04x)",
                                sidrid_str_d, flags)
                    
#                    # Has this already been subscribed?
#                    elif self.parent.net_subs.contains(sid, rid):
#                        debug_print(PSIRP_DBG_INFO,
#                                    "Subscription ignored "
#                                    "(already subscribed)")
#                        # Should we support re-subscribing?
#
#                        continue # for sid, rid in subs
                    
                    # Is this a non-network scope?
                    if re.match(self.parent.parent.sid_pattern, # XXXX
                                sid_str) is None:
                        debug_print(PSIRP_DBG_GARB,
                                    "Subscription ignored "
                                    "(%s is not a network scope)", sid_str)
                        continue # for sid, rid in subs
                    
                    # Is this publication already available locally?
                    # XXXXX
                    elif not (flags & PS_FLAGS_LOCAL_NETSUB):
                        try:
                            pub = subscribe_local(sid, rid)
                            
                            debug_print(PSIRP_DBG_GARB,
                                        "Subscription ignored "
                                        "(already stored locally)")
                            continue # for sid, rid in subs
                        except NotFoundError, e:
                            # Publication not available locally
                            pass
                    
                    md = None
                    if self.parent.parent.net.metadata.super.contains(sid, rid):
                        md = \
                            self.parent.parent.net.metadata.latest_entry(sid,
                                                                         rid)[1]
                    if md:
                        # We already have metadata, so either we are a
                        # local RZV node, or we have made another
                        # subscription while metadata for a previous
                        # subscription has been in reception.
                        # XXX: Should the latter case be handled in some
                        #      special manner?
                        sub_fids = self.parent.net_subs.contains(sid, rid)
                        if not sub_fids:
                            sub_fids = SubFIds()
                            self.parent.net_subs.add(sid, rid, sub_fids)
                        sub_fids.set_local_fid(flags)
                        
                        if (self.parent.parent.is_rzv_node \
                                and (flags & PS_FLAGS_NET_FUTUREONLY)):
                            # In this case, we don't want to get
                            # anything from the source yet
                            continue
                        
                        debug_print(PSIRP_DBG_INFO,
                                    "Already have metadata, "
                                    "subscribing to data, SId/RId=%s",
                                    sidrid_str_d)

                        self.parent.data_subs.add(sid, rid, md.vrid)
                        
                        self.parent.parent.net.publish_ipc_md(
                            libpsirp_py.PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK,
                            md)
                    else:
                        sub_fids = self.parent.net_subs.contains(sid, rid)
                        if not sub_fids:
                            sub_fids = SubFIds()
                            self.parent.net_subs.add(sid, rid, sub_fids)
                        sub_fids.set_local_fid(flags)
                        debug_print(
                            PSIRP_DBG_INFO,
                            "Subscription stored, SId/RId=%s",
                            sidrid_str_d)
                        if not self.parent.parent.is_rzv_node:
                            # First we need to subscribe to the metadata
                            debug_print(PSIRP_DBG_INFO,
                                        "Subscribing to metadata "
                                        "from the RZV node, SId/RId=%s",
                                        sidrid_str_d)
                            self.parent.parent.net.publish_ipc_md(
                                libpsirp_py.PSIRP_HDR_RZV_SUBSCRIBE_METADATA,
                                Metadata(sid, rid),
                                md_sub_flags=flags)
                
                debug_return()
        
        def init(self, pskq):
            debug_enter()
            
            FILENAME = "/pubsub/subs"
            subs_file = open(FILENAME)
            
            subs_pub = self.SubsPub(subs_file, self)
            subs_pub_fd = subs_pub.fd
            subs_pub_fflags = \
                NOTE_PUBLISH | select.KQ_NOTE_WRITE | select.KQ_NOTE_ATTRIB
            pskq.custom_command(subs_pub.fd, fflags=subs_pub_fflags)
            pskq.pubs[subs_pub_fd] = subs_pub # XXX
            
            debug_return()
            
    
    class Net(object):
        """Network events."""
        
        def __init__(self, parent, ipc_sid, ipc_local_rid, ipc_net_rid):
            self.parent = parent # Subscriber
            self.ipc_sid = ipc_sid
            self.ipc_local_rid = ipc_local_rid
            self.ipc_net_rid = ipc_net_rid
            self.ipc_net_pub = None
            
            self.metadata = SIdRIdVRIdItemDict()
        
        def init(self, pskq):
            debug_enter()
            
            # Subscribe to network-triggered events (inbound in this context)
            try:
                ipc_pub = subscribe_local(self.ipc_sid, self.ipc_net_rid)
            except NotFoundError, e:
                debug_print(PSIRP_DBG_GARB,
                            "IPC publication does not yet exist, "
                            "creating it (%s)",
                            idstoa_d(self.ipc_sid, self.ipc_net_rid))
                
                tmp_pub = createpub(self.ipc_sid, self.ipc_net_rid)
                
                try:
                    ipc_pub = subscribe_sync_local(self.ipc_sid,
                                                   self.ipc_net_rid,
                                                   1.0)
                except NotFoundError:
                    debug_print(PSIRP_DBG_WARN,
                                "Could not subscribe to newly created "
                                "IPC publication")
                    ipc_pub = tmp_pub # This one is just as good, actually
            ipc_pub.saved_version_index = ipc_pub.version_index
            
            reg_args = (self.ipc_sid,
                        next_rid(self.ipc_net_rid),
                        PS_FLAGS_LOCAL_LOCALSUB|PS_FLAGS_LOCAL_FUTUREONLY,
                        self.get_next_rid_evh(pskq))
            next_ipc_pub = pskq.register_advance_subscription(*reg_args)
            
            self.ipc_net_pub = ipc_pub
            ipc_pub.handle_event = self.get_event_handler()
            pskq.register(ipc_pub, True); del ipc_pub
            
            debug_return()
        
        def get_next_rid_evh(self, pskq):
            
            def handle_event(event, pub):
                pskq.register(pub, False)
                ipc_net_rid = copybuf(pub.rid)
                reg_args = (self.ipc_sid,
                            next_rid(ipc_net_rid),
                            PS_FLAGS_LOCAL_LOCALSUB|PS_FLAGS_LOCAL_FUTUREONLY,
                            self.get_next_rid_evh(pskq))
                next_ipc_pub = pskq.register_advance_subscription(*reg_args)
                
                pub.handle_event = self.get_event_handler()
                self.ipc_net_pub = pub
                self.ipc_net_rid = ipc_net_rid
                
                debug_print(PSIRP_DBG_INFO,
                            "New IPC net RId: %s",
                            idtoa_d(self.ipc_net_rid))
                
                pub.handle_event(event, pub)
                
                pskq.register(pub, True)
            
            return handle_event
        
        def get_event_handler(self):
            # This nesting allows us to use self in the inner callback function.
            
            def handle_event(event, ipc_pub):
                debug_enter()
                
                # Process all versions since the last seen one                
                for version in ipc_pub.get_versions_since_saved_index():
                    handle_version(version)
                
                debug_return()
            
            def handle_version(ipc_pub_version):
                debug_enter()
                
                metadata = \
                    libpsirp_py.psirp_py_pub_hdrs_metadata(ipc_pub_version.pubp)
                
                sid     = copybuf(metadata.getsid())
                rid     = copybuf(metadata.getrid())
                vrid    = copybuf(metadata.getvrid())
                # Collected FId to the pub'r or sub'r:
                fid     = copybuf(metadata.getfid())
                pub_len = metadata.len
                type    = metadata.rzvhdr_type
                flags   = metadata.flags
                
                rid_str = idtoa(rid)
                
#                debug_print(PSIRP_DBG_INFO,
#                            "Received metadata:\n"
#                            "         SId/RId: %s\n"
#                            "         vRId:    %s\n"
#                            "         FId:     %s\n"
#                            "         len:     %d\n"
#                            "         type:    0x%02x",
#                            idstoa_d(sid, rid),
#                            idtoa_d(vrid),
#                            idtoa_d(fid),
#                            pub_len,
#                            type)
                
                if type == libpsirp_py.PSIRP_HDR_RZV_PUBLISH_METADATA:
                    # Somebody in the network published something
                    # (and we are a RZV node),
                    # or we have subscribed to a publication.
                    debug_print(PSIRP_DBG_INFO,
                                "Received 'publish metadata' "
                                "from the blackboard")
                    
                    # Check what we have just published ourself -
                    # a notification might have bounced back if we have
                    # also subscribed to that. (XXX)
                    if self.parent.own_pubs.contains(sid, rid, vrid):
                        debug_print(PSIRP_DBG_INFO,
                                    "Ignoring metadata that was published "
                                    "by us, RId/vRId=%s",
                                    idstoa_d(rid, vrid))
                        self.parent.own_pubs.remove(sid, rid, vrid)
                        return debug_return()
                    
                    # Check if this publication version exists locally
                    local_version = None
                    try:
                        local_version = subscribe_local(rid, vrid)
                    except NotFoundError, e:
                        # We don't seem to have this version yet
                        pass
                    
                    # Add to metadata map
                    md = Metadata(sid, rid, vrid, fid, pub_len)
                    self.metadata.add(sid, rid, vrid, md)
                    debug_print(PSIRP_DBG_INFO,
                                "Metadata stored, RId=%s", rid_str)
                    
                    # If we have a local subscription in our  map, we have
                    # previously subscribed to it and want to get the data.
                    # If we have any remote subscriptions, we should send
                    # them this metadata.
                    sub_fids = self.parent.subs.net_subs.contains(sid, rid)
                    if sub_fids:
                        # Local subscriptions
                        if sub_fids.local_fid_doc or sub_fids.local_fid_pst:
                            debug_print(PSIRP_DBG_INFO,
                                        "Subscribe to data, RId=%s", rid_str)
                            
                            self.parent.subs.data_subs.add(sid, rid, md.vrid)
                            
                            if not local_version:
                                self.publish_ipc_md(
                                    libpsirp_py.PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK,
                                    md)
                            else:
                                debug_print(PSIRP_DBG_INFO,
                                            "Reuse data from locally stored "
                                            "version, vRId=%s",
                                            idtoa_d(local_version.vrid))
                                local_version.publish(sid, rid)
                        
                        # Remote subscriptions
                        fid_out = sub_fids.get_remote_fid()
                        if fid_out:
                            debug_print(PSIRP_DBG_INFO,
                                        "Send out metadata to subscribers, "
                                        "RId/FId=%s",
                                        idstoa_d(rid, fid_out))
                            self.publish_ipc_md(
                                libpsirp_py.PSIRP_HDR_RZV_PUBLISH_METADATA,
                                md,
                                subr_fid=fid_out)
                            if sub_fids.remote_fid_doc:
                                # Remote doc subscribers are on their own
                                # after this.
                                sub_fids.remote_fid_doc = None
                                if sub_fids.is_empty():
                                    self.parent.subs.net_subs.remove(sid, rid)
                    
                elif type == libpsirp_py.PSIRP_HDR_RZV_SUBSCRIBE_METADATA:
                    # Somebody in the network subscribed to metadata
                    debug_print(PSIRP_DBG_INFO,
                                "Recevied 'subscribe metadata' "
                                "from the blackboard")
                    
                    sub_fids = self.parent.subs.net_subs.contains(sid, rid)
                    
                    if (flags & PS_FLAGS_NET_FUTUREONLY):
                        # The subscriber only wants future versions
                        pass
                    elif self.metadata.super.contains(sid, rid) \
                            and self.metadata.latest_entry(sid, rid):
                        # We have the corresponding metadata, so let's
                        # publish it
                        md = self.metadata.latest_entry(sid, rid)[1]
                        # (Version ignored)
                        
                        md_out = Metadata(sid, rid, md.vrid, fid, md.len)
                        self.publish_ipc_md(
                            libpsirp_py.PSIRP_HDR_RZV_PUBLISH_METADATA,
                            md_out,
                            subr_fid=fid)
                    else:
                        # Check if we have the publication locally
                        try:
                            spub = subscribe_local(sid, rid)
                            if spub.type != PS_PUB_DATA:
                                debug_print(
                                    PSIRP_DBG_WARN,
                                    "Subscription to non-data publication")
                                return debug_return()
                            spub_vrid = spub.vrid
                        except NotFoundError, e:
                            debug_print(
                                PSIRP_DBG_WARN,
                                "Subscription to unknown publication")
                            if not sub_fids:
                                sub_fids = SubFIds()
                                self.parent.subs.net_subs.add(sid, rid,
                                                              sub_fids)
                            if not (flags & PS_FLAGS_NET_PERSISTENT):
                                sub_fids.add_remote_fid(fid, flags)
                            debug_print(
                                PSIRP_DBG_INFO,
                                "Network subscription stored, SId/RId=%s",
                                idstoa_d(sid, rid))
                                # XXX: Can be duplicated below...
                        else:
                            md_out = Metadata(sid, rid, spub_vrid, fid,
                                              spub.len)
                            self.publish_ipc_md(
                                libpsirp_py.PSIRP_HDR_RZV_PUBLISH_METADATA,
                                md_out,
                                subr_fid=fid)
                    
                    if flags & \
                            (PS_FLAGS_NET_PERSISTENT | PS_FLAGS_NET_FUTUREONLY):
                        if not sub_fids:
                            sub_fids = SubFIds()
                            self.parent.subs.net_subs.add(sid, rid, sub_fids)
                        sub_fids.add_remote_fid(fid, flags)
                        debug_print(
                            PSIRP_DBG_INFO,
                            "Network subscription stored, SId/RId=%s",
                            idstoa_d(sid, rid))
                
                elif type == libpsirp_py.PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK:
                    # Somebody in the network subscribed to data
                    debug_print(PSIRP_DBG_INFO,
                                "Received 'subscribe data' from the blackboard")
#                    time.sleep(5) # XXX: Enable only for debugging
                    
                    if self.metadata.contains(sid, rid, vrid):
                        # We have the corresponding metadata, but
                        # presumably not the data. (?) We pass on this
                        # subscription to the publisher.
                        debug_print(PSIRP_DBG_INFO,
                                    "Relay subscription to data chunks")
                        md = self.metadata[sid][rid][vrid]
                        self.publish_ipc_md(
                            libpsirp_py.PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK,
                            md,
                            extra_fid=fid,
                            relay=True)
                    else:
                        # Check if we have this publication locally.
                        # If we have it, send it out.
                        try:
                            # RId in scope?
                            pub = subscribe_local(sid, rid)
                            if vrid != EMPTY_RID:
                                # Version-RId in publication?
                                #
                                # XXX: We don't know if this version was
                                #      published in the given scope;
                                #      currently that just cannot be verified.
                                vpub = subscribe_local(rid, vrid)
                                vpub_vrid = vpub.vrid
                                vpub_len  = vpub.len
                            else:
                                # Just get the latest version in this case
                                vpub_vrid = pub.vrid
                                vpub_len  = pub.len
                            
                            md = Metadata(sid, rid, vpub_vrid, fid, vpub_len)
#                            debug_print(PSIRP_DBG_INFO,
#                                        "Publish data chunks:\n"
#                                        "         SId/RId: %s\n"
#                                        "         vRId:    %s\n"
#                                        "         FId:     %s\n"
#                                        "         len:     %d",
#                                        idstoa_d(sid, rid),
#                                        idtoa_d(vpub_vrid),
#                                        idtoa_d(fid),
#                                        vpub_len)
                                                        
                            self.publish_ipc_md(
                                libpsirp_py.PSIRP_HDR_RZV_PUBLISH_DATACHUNK,
                                md)
                        except NotFoundError, e:
                            debug_print(
                                PSIRP_DBG_INFO,
                                "Subscription to unknown publication")
                
                elif type == libpsirp_py.PSIRP_HDR_RZV_PUBLISH_DATACHUNK:
                    debug_print(PSIRP_DBG_WARN,
                                "Received 'publish datachunk' "
                                "from the blackboard "
                                "-- unexpectedly and unrequestedly!")
                
                else:
                    debug_print(PSIRP_DBG_WARN,
                                "Unknown IPC publication type: %d", type)
                return debug_return()
            
            return handle_event
        
        def publish_ipc_md(self, type, md,
                           subr_fid=None, md_sub_flags=0x00,
                           extra_fid=None, relay=None):
            debug_enter()
            
            # Create publication and "cast" it to metadata
            if type == libpsirp_py.PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK:
                # This is special case. We add extra information to the MD.
                pub = Publication.from_pubp(
                    libpsirp_py.psirp_py_create_md_ext_pub(None))
                metadata_ext = \
                    libpsirp_py.psirp_py_pub_hdrs_metadata_ext(pub.pubp)
                if extra_fid is not None and relay is not None:
                    # This FId goes into the _metadata_
                    metadata_ext.setextfid(extra_fid)
                    # Probably always true if set
                    metadata_ext.md_ext.relay = relay
                else:
                    metadata_ext.setextfid(EMPTY_FID)
                    metadata_ext.md_ext.relay = False
                del metadata_ext
            else:
                # This is the normal case.
                pub = Publication.from_pubp(
                    libpsirp_py.psirp_py_create_md_pub(None))
            metadata = libpsirp_py.psirp_py_pub_hdrs_metadata(pub.pubp)
            
            metadata.rzvhdr_type = type
            metadata.hdr_type = libpsirp_py.PSIRP_HDR_MD
            metadata.setsid(md.sid)
            metadata.setrid(md.rid)
            metadata.setvrid(md.vrid)
            metadata.len = md.len
            
            def pubipcmd(fid, metadata, pub):
                debug_enter()
                metadata.setfid(fid)
                debug_print(PSIRP_DBG_INFO,
                            "Publishing metadata on the blackboard:\n%s",
                            metadata)
                pub.publish(self.ipc_sid, self.ipc_local_rid)
                
                if pub.version_count >= 100:
                    # Ideally, we would do this before publishing, not after.
                    self.ipc_local_rid = next_rid(self.ipc_local_rid)
                    debug_print(PSIRP_DBG_INFO,
                                "Switching to next IPC local RId: %s",
                                idtoa_d(self.ipc_local_rid))
                
                debug_return()
            
            if type == libpsirp_py.PSIRP_HDR_RZV_SUBSCRIBE_METADATA:
                metadata.flags |= md_sub_flags & 0x0f # XXX
                pubipcmd(md.fid, metadata, pub)
                
            elif type == libpsirp_py.PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK \
                    or type == libpsirp_py.PSIRP_HDR_RZV_PUBLISH_DATACHUNK:
                pubipcmd(md.fid, metadata, pub)
                
            else: # libpsirp_py.PSIRP_HDR_RZV_PUBLISH_METADATA
                pubipcmd(subr_fid, metadata, pub)
            
            debug_return()
        
    
    class Scope(object):
        """Local publishes."""
        
        def __init__(self, parent, parent_sid, sid):
            self.parent = parent
            self.parent_sid = parent_sid
            self.sid = sid
            
            self.rid_count = 0
        
        def init(self, pskq, is_net_scope=None):
            debug_enter()
            
            # Subscribe to scope
            debug_print(PSIRP_DBG_GARB, "Subscribe to scope")
            
            self.sid_str = idtoa(self.sid)
            if is_net_scope is None:
                self.is_net_scope = (re.match(self.parent.sid_pattern,
                                              self.sid_str) is not None) # XXX
            else:
                self.is_net_scope = is_net_scope
            
            scope_pub = subscribe_local(self.sid, self.sid)
            
            debug_print(PSIRP_DBG_GARB,
                        "Read RIds in scope with SId: %s",
                        idtoa_d(self.parent_sid))
            scope_data = scope_pub.get_rids()
            
            # Read and process initial scope contents
            for rid in scope_data:
                self.init_pub(pskq, copybuf(rid))
            
            self.rid_count = len(scope_data)
            debug_print(PSIRP_DBG_GARB,
                        "Scope initialized, %d RIds", self.rid_count)
        
        def init_pub(self, pskq, rid):
            debug_enter()
            
            sid_str_d = idtoa_d(self.sid)
            rid_str = idtoa(rid)
            
            # Subscribe to this publication
            debug_print(PSIRP_DBG_GARB,
                        "Subscribe to SId/RId: %s/%s", sid_str_d, rid_str)
            pub = subscribe_local(self.sid, rid)
            pub_len = pub.len
            
            vrid = copybuf(pub.vrid)
            vrid_str = idtoa(vrid)
            
            # Register to its events
            if pub.type == PS_PUB_SCOPE:
                is_net_scope = (re.match(self.parent.sid_pattern,
                                         rid_str) is not None) # XXX
                if rid == ROOT_SCOPE_SID or is_net_scope:
                    if rid == self.sid:
                        debug_print(PSIRP_DBG_INFO,
                                    "Registering to scope events, "
                                    "SId=%s", rid_str)
                        pub.handle_event = self.get_scope_event_handler()
                        pskq.register(pub, True); del pub
                    else:
                        debug_print(PSIRP_DBG_GARB,
                                    "Initializing subscope, "
                                    "SId=%s", rid_str)
                        subscope = self.parent.Scope(self.parent,
                                                     self.sid, rid)
                        subscope.init(pskq, is_net_scope)
                else:
                    debug_print(PSIRP_DBG_INFO,
                                "SId=%s is not a network scope", rid_str)
            else:
                debug_print(PSIRP_DBG_INFO,
                            "Registering to publication events, "
                            "RId=%s", rid_str)
                # XXX: This could be re-publication in another scope,
                #      but right now we always treat it as a new
                #      publication.
                pub.handle_event = self.get_pub_event_handler()
                pub.saved_version_index = pub.version_index
                pskq.register(pub, True); del pub
                
                self.publish_net_metadata(self.sid, rid, vrid, pub_len)
            
            debug_return()
        
        def get_scope_event_handler(self):
            
            # No need to think about versions (at least not yet)
            def handle_event(event, scope_pub):
                debug_enter()
                
                if event.fflags & NOTE_PUBLISH:
                    # Something was published in the scope
                    # XXX: We assume that items can only be added,
                    #      and not removed.
                    old_rid_count = self.rid_count
                    new_rids = scope_pub.get_rids(old_rid_count)
                    new_rid_count = old_rid_count + len(new_rids)
                    debug_print(PSIRP_DBG_GARB,
                                "Old RId count: %d, new RId count: %d",
                                old_rid_count, new_rid_count)
                    
                    if new_rid_count > old_rid_count:
                        for rid in new_rids:
                            debug_print(PSIRP_DBG_INFO,
                                        "New scope entry: SId/RId=%s",
                                        idstoa_d(self.sid, rid))
                            self.init_pub(self.parent.pskq, copybuf(rid))
                        
                        self.rid_count = new_rid_count
                else:
                    debug_print(PSIRP_DBG_WARN, "Scope subscribed?")
                
                debug_return()
            
            return handle_event
        
        def get_pub_event_handler(self):
            
            def handle_version(sid, rid, version):
                debug_enter()
                
                vrid = copybuf(version.vrid)
                version_len = version.len
                
                self.publish_net_metadata(sid, rid, vrid, version_len)
                
                debug_return()
            
            def handle_event(event, pub):
                debug_enter()
                
                if not (event.fflags & NOTE_PUBLISH):
                    return debug_return()
                
                sid = copybuf(pub.sid)
                rid = copybuf(pub.rid)
                
                debug_print(PSIRP_DBG_INFO,
                            "Publication update, SId/RId=%s",
                            idstoa_d(sid, rid))
                
                # Process all versions since the last seen one
                for version in pub.get_versions_since_saved_index():
                    handle_version(sid, rid, version)
                
                debug_return()
            
            return handle_event
        
        def publish_net_metadata(self, sid, rid, vrid, pub_len):
            # Called when publications are initialized or updated
            debug_enter()
            
            if not self.is_net_scope:
                debug_print(PSIRP_DBG_INFO,
                            "SId=%s is not a network scope",
                            self.sid_str)
                return debug_return()
            
            data_sub = False
            if self.parent.subs.data_subs.contains(sid, rid, vrid):
                data_sub = True
            
            stored_md = self.parent.net.metadata.super.contains(self.sid, rid)
            if stored_md:
                # Remove metadata, but only if we're not a RZV node or
                # if this seems to be a newer version.
                # The former check implies that data is always subscribed
                # from the source instead of the RZV node itself.
                if not self.parent.is_rzv_node:
                    self.parent.net.metadata.remove(self.sid, rid, vrid)
                elif stored_md.latest_entry[0] != vrid:
                    self.parent.net.metadata.latest_entry = None
            
            sub_fids = self.parent.subs.net_subs.contains(self.sid, rid)
            fid_out = None
            
            if sub_fids:
                # Local subscription
                if sub_fids.local_fid_doc:
                    # This publication had been subscribed previously.
                    # Remove the pending subscription.
                    # XXX: What if NETSUB and only local update?
                    sub_fids.local_fid_doc = None
                    if sub_fids.is_empty():
                        self.parent.subs.net_subs.remove(self.sid, rid)
                
                # We have a local subscription to data
                if data_sub:
                    self.parent.subs.data_subs.remove(sid, rid, vrid)
                
                # Remote subscriptions
                # - We assume that only local RZV nodes know about
                #   remote subscribers.
                # - We also assume that if we have a data subscription
                #   for ourself, we've already earlier received and
                #   sent out metadata and won't need to do it now (if
                #   we do it twice, our subscribers think that it's
                #   yet a new version).
                fid_out = sub_fids.get_remote_fid()
                if fid_out and not data_sub:
                    debug_print(PSIRP_DBG_INFO,
                                "Send out metadata, RId/FId=%s",
                                idstoa_d(rid, fid_out))
                    self.parent.net.publish_ipc_md(
                        libpsirp_py.PSIRP_HDR_RZV_PUBLISH_METADATA,
                        Metadata(sid, rid, vrid, None, pub_len),
                        subr_fid=fid_out)
                    
                    if sub_fids.remote_fid_doc:
                        # Remote doc subscribers are on their own
                        # after this.
                        sub_fids.remote_fid_doc = None
                        if sub_fids.is_empty():
                            self.parent.subs.net_subs.remove(sid, rid)
            
            if fid_out is None and not data_sub:
                # We have not subscribed to this data, and we don't know
                # about any remote subscribers either.
                
                # If we are not a RZV node, we'd want to ignore any
                # notifications that "bounce back" to us. That could
                # happen if we have a pending subscription.
                # But if we are a RZV node, we do want to know when
                # somebody publishes metadata about new pubs. In
                # the latter case, nothing will "bounce back".
                if not self.parent.is_rzv_node \
                        and self.parent.subs.net_subs.contains(sid, rid):
                    self.parent.own_pubs.add(sid, rid, vrid) # XXX
                
                # Issue IPC command to get new metadata published
                # into the network.
                # XXX: Maybe we should do this only if we aren't a RZV node.
                md = Metadata(sid, rid, vrid, EMPTY_FID, pub_len)
                self.parent.net.publish_ipc_md(
                    libpsirp_py.PSIRP_HDR_RZV_PUBLISH_METADATA,
                    md,
                    subr_fid=EMPTY_FID)
            
            debug_return()
    
    def __init__(self, sid_pattern, ipc_sid, ipc_local_rid, ipc_net_rid,
                 is_rzv_node):
        self.sid_pattern = re.compile(sid_pattern)
        
        self.pskq = PubSubKQueue()
        self.subs = self.Subs(self)
        self.net = self.Net(self, ipc_sid, ipc_local_rid, ipc_net_rid)
        self.root_scope = self.Scope(self, ROOT_SCOPE_SID, ROOT_SCOPE_SID)
        
        self.is_rzv_node = is_rzv_node # XXXX
        self.own_pubs = SIdRIdVRIdCountDict()
    
    def laird_listen(self):
        debug_enter()
        
        # Register to events and initialize handlers
        self.subs.init(self.pskq)
        self.net.init(self.pskq)
        self.root_scope.init(self.pskq)
        
        # Listen
        debug_print(PSIRP_DBG_INFO, "Listening to events")
        try:
            while True:
                publ = self.pskq.listen()
                for ev, pub in publ:
                    if not isinstance(pub, Publication):
                        if ev.ident == TIMER_IDENT:
                            if ev.udata == errno.EINTR:
                                raise KeyboardInterrupt()
                            raise RuntimeError()
                        
                        debug_print(PSIRP_DBG_WARN,
                                    "Not a publication: %r, %r", ev, pub)
                        continue
#                    print("Refcount before handle(): %d"%sys.getrefcount(None))
                    pub.handle_event(ev, pub)
#                    print("Refcount after  handle(): %d"%sys.getrefcount(None))
        except KeyboardInterrupt:
            debug_print(PSIRP_DBG_INFO, "Rendezvous listener interrupted")
        except:
            debug_print(PSIRP_DBG_ERR,
                        "Rendezvous listener:\n%s",
                        traceback.format_exc())
        
        # Cleanup
        debug_print(PSIRP_DBG_GARB, "Cleaning up")
        self.pskq.close()
        
        debug_print(PSIRP_DBG_GARB, "Done")
        debug_return()
    


def createpub(sid, rid):
    """Create and publish a publication."""
    pub = create(1)
    pub.publish(sid, rid)
    return pub

def next_rid(rid):
    """Returns incremented RId."""
    # XXX: Use psirp_idinc instead?
    rid_as_array = array.array('B', rid[:])
    
    i = len(rid_as_array)-1
    while i >= 0:
        if rid_as_array[i] < 0xff:
            rid_as_array[i] += 1
            break
        rid_as_array[i] = 0x00
        i -= 1
    
    return buffer(rid_as_array)

def copybuf(buf):
    """Make a (read-only) copy of a buffer."""
    return buffer(buf[:])

def fidor(fid1, fid2):
    """OR the new fid1 with fid2.""" # (A bit inefficient.)
    arr = array.array('c', fid1)
    for i in xrange(PSIRP_ID_LEN):
        arr[i] = chr(ord(arr[i]) | ord(fid2[i]))
    return buffer(arr)

def idtoa_d(id):
    """Identifier conversion if debug prints are on."""
    if PSIRP_PY_DEBUG:
        return idtoa(id)
    return ""

def idstoa_d(sid, rid):
    """Identifier conversion if debug prints are on."""
    if PSIRP_PY_DEBUG:
        return idstoa(sid, rid)
    return ""



class IdDict(dict):
    pass


class SIdRIdDict(IdDict):
    # {SId<buffer>:
    #      {RId<buffer>:
    #           counter<int>|item<object>,
    #       ...},
    #  ...}
    
    def __init__(self, count=False):
        self.count = count
    
    def add(self, sid, rid, item=None):
        if sid not in self:
            self[sid] = IdDict()
        if self.count and rid in self[sid]:
            self[sid][rid] += 1
        else:
            if item is None:
                item = 1
            self[sid][rid] = item
    
    def remove(self, sid, rid):
        if sid in self and rid in self[sid]:
            if self.count and self[sid][rid] > 1:
                self[sid][rid] -= 1
            else:
                del self[sid][rid]
            if len(self[sid]) == 0:
                del self[sid]
    
    def contains(self, sid, rid):
        return (self[sid][rid] if sid in self and rid in self[sid]
                else 0)


class SIdRIdVRIdCountDict(SIdRIdDict):
    # {SId<buffer>:
    #      {RId<buffer>:
    #           {VRId<buffer>:
    #                counter<int>,
    #            ...},
    #       ...},
    #  ...}
    
    def __init__(self):
        super(type(self), self).__init__()
    
#     def _print_sid_rid_vrid(self, sid, rid, vrid): # XXX: Only for debugging
#         frame1 = sys._getframe(1) # caller's frame (i.e., operation)
#         frame2 = sys._getframe(2) # outer caller's frame
#         op = frame1.f_code.co_name
#         who = frame2.f_code.co_name
#         where = frame2.f_lineno
#         str1 = idstoa_d(sid, rid)
#         str2 = idtoa_d(vrid)
#         print("%s(%d): %s(%s/%s)", (who, where, op, str1, str2))
    
    def add(self, sid, rid, vrid):
#        self._print_sid_rid_vrid(sid, rid, vrid) # XXX
        vrid_dict = super(type(self), self).contains(sid, rid)
        if vrid_dict:
            if vrid in vrid_dict:
                vrid_dict[vrid] += 1
            else:
                vrid_dict[vrid] = 1
        else:
            vrid_dict = IdDict()
            vrid_dict[vrid] = 1
            super(type(self), self).add(sid, rid, vrid_dict)
        
    def remove(self, sid, rid, vrid):
#        self._print_sid_rid_vrid(sid, rid, vrid) # XXX
        vrid_dict = super(type(self), self).contains(sid, rid)
        if vrid_dict:
            if vrid in vrid_dict:
                if vrid_dict[vrid] > 1:
                    vrid_dict[vrid] -= 1
                else:
                    del vrid_dict[vrid]
                    if len(vrid_dict) == 0:
                        super(type(self), self).remove(sid, rid)
    
    def contains(self, sid, rid, vrid):
#        self._print_sid_rid_vrid(sid, rid, vrid) # XXX
        vrid_dict = super(type(self), self).contains(sid, rid)
        return (vrid_dict[vrid] if vrid_dict and vrid in vrid_dict
                else 0)


class SIdRIdVRIdItemDict(SIdRIdDict):
    # {SId<buffer>:
    #      {RId<buffer>:
    #           {VRId<buffer>:
    #                item,
    #            ...},
    #       ...},
    #  ...}
    
    def __init__(self):
        super(type(self), self).__init__()
        
    def add(self, sid, rid, vrid, item):
        vrid_dict = super(type(self), self).contains(sid, rid)
        if vrid_dict:
            vrid_dict[vrid] = item
        else:
            vrid_dict = IdDict()
            vrid_dict[vrid] = item
            super(type(self), self).add(sid, rid, vrid_dict)
        vrid_dict.latest_entry = (vrid, item)
    
    def remove(self, sid, rid, vrid):
        vrid_dict = super(type(self), self).contains(sid, rid)
        if vrid_dict:
            if vrid in vrid_dict:
                del vrid_dict[vrid]
                if vrid == vrid_dict.latest_entry:
                    vrid_dict.latest_entry = None
                if len(vrid_dict) == 0:
                    super(type(self), self).remove(sid, rid)
    
    def contains(self, sid, rid, vrid):
        vrid_dict = super(type(self), self).contains(sid, rid)
        return (vrid_dict[vrid] if vrid_dict and vrid in vrid_dict
                else 0)
    
    def latest_entry(self, sid, rid):
        vrid_dict = super(type(self), self).contains(sid, rid)
        if vrid_dict:
            return vrid_dict.latest_entry
        return None

    @property
    def super(self):
        return super(type(self), self)


class SubFIds(object):
    
    def __init__(self):
        # Local FIds should be None or EMPTY_FID.
        # If the persistent FId is defined, the document FId is meaningless.
        self.local_fid_pst = None
        self.local_fid_doc = None
        # Remote FIds should be None or ORed FIds.
        # Document and persistent FIds are stored separately.
        self.remote_fid_pst = None
        self.remote_fid_doc = None
    
    def set_local_fid(self, flags):
        if flags & PS_FLAGS_NET_PERSISTENT: # XXX
            self.local_fid_pst = EMPTY_FID
            if self.local_fid_doc is not None:
                self.local_fid_doc = None
        else:
            if self.local_fid_pst is None:
                self.local_fid_doc = EMPTY_FID
    
    def add_remote_fid(self, fid, flags):
        if flags & PS_FLAGS_NET_PERSISTENT: # XXX
            if self.remote_fid_pst is None:
                self.remote_fid_pst = fid
            else:
                self.remote_fid_pst = fidor(self.remote_fid_pst, fid)
        else:
            if self.remote_fid_doc is None:
                self.remote_fid_doc = fid
            else:
                self.remote_fid_doc = fidor(self.remote_fid_doc, fid)
    
    def get_remote_fid(self):
        fid_doc = self.remote_fid_doc
        fid_pst = self.remote_fid_pst
        if fid_doc and fid_pst:
            return fidor(fid_doc, fid_pst)
        elif fid_doc:
            return fid_doc
        elif fid_pst:
            return fid_pst
        return None
    
    def is_empty(self):
        return self.local_fid_pst   is None \
            and self.remote_fid_pst is None \
            and self.local_fid_doc  is None \
            and self.remote_fid_doc is None
    

class Metadata(object):
    
    def __init__(self, sid, rid, vrid=EMPTY_RID, fid=EMPTY_FID, len=0):
        self.sid  = sid
        self.rid  = rid
        self.vrid = vrid
        self.fid  = fid
        self.len  = len


def rzv_node_check(config_file_name): # XXX
    file = None
    
    try:
        file = open(config_file_name, 'r')
        line_num = -1
        
        for line in file:
            line_num += 1
            debug_print(PSIRP_DBG_GARB, "%02d: %r", line_num, line)
            
            # First get rid of comments and whitespace, then split at semicolons
            line_data = line.split('#')[0].strip().split(";")
            
            # Check format
            if len(line_data) != 3:
                if len(line_data) == 1 and len(line_data[0]) == 0:
                    # This is probably an empty line or just a comment
                    continue
                # This is a line that we don't understand
                debug_print(PSIRP_DBG_WARN,
                            "Cannot parse line %d in %s: %r",
                            line_num, config_file_name, line)
                continue
            
            # Look at the data in the line
            if_name, if_type, lid_str = map(str.strip, line_data)
            if if_type.lower() == "def":
                # Default route specification
                lid = atoid(lid_str)
                if idcmp(lid, EMPTY_FID) != 0:
                    # Default route is not zero
                    debug_print(PSIRP_DBG_INFO,
                                "Found default route entry on line %d in %s: "
                                "\"%s;%s;%s\"",
                                line_num, config_file_name,
                                if_name, if_type, idtoa_d(lid))
                    return False
        
        # All default routes are zero (or none have been specified)
        debug_print(PSIRP_DBG_INFO,
                    "No non-zero default route entries found in %s, "
                    "so this is probably a local rendezvous node",
                    config_file_name);
        return True
    
    except Exception, e:
        debug_print(PSIRP_DBG_ERR,
                    "Configuration file parsing error:\n%s",
                    traceback.format_exc())
        # In this case, just assume that all routes are zero
        return True
    finally:
        try:
            if file is not None:
                file.close()
        except Exception, e:
            print(e)



def main():
    import getopt
        
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "s:r:q:t:ch", [])
        #print(opts, args)
    except getopt.GetoptError, err:
        print(str(err))
        sys.exit(1)
    
    debug_level = 0
    debug_colors = False
    sid_pattern = DEFAULT_LOCAL_SID_PATTERN
    ipc_sid = DEFAULT_IPC_SID
    ipc_local_rid = DEFAULT_IPC_LOCAL_RID
    ipc_net_rid = DEFAULT_IPC_NET_RID
    
    for o, a in opts:
        if o == "-h":
            print("%s %s" \
                      % (str(__file__).split("/")[-1],
                         "[-s sid_pattern -r ipc_local_rid -q ipc_net_rid "
                         "-t debug_level -c -h]"))
            sys.exit()
        elif o == "-r":
            ipc_local_rid = atoid(a)
        elif o == "-q":
            ipc_net_rid = atoid(a)
        elif o == "-t":
            debug_level = int(a)
        elif o == "-c":
            debug_colors = True
        else:
            assert False, "Unhandled option: %r" % o

    def sigint_handler(signal_number, stack_frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGINT, sigint_handler)
    
    debug_init(debug_level, debug_colors)
    
    # XXXX: It's useful to know whether we are a RZV node or not.
    #       However, we're checking it in a rather inelegant way here...
    is_rzv_node = rzv_node_check(CONFIG_FILE_NAME)
    
    kwargs = {"sid_pattern": sid_pattern,
              "ipc_sid": ipc_sid,
              "ipc_local_rid": ipc_local_rid,
              "ipc_net_rid": ipc_net_rid,
              "is_rzv_node": is_rzv_node}
    
    s = Subscriber(**kwargs)
    s.laird_listen()


if __name__ == "__main__":
    main()

