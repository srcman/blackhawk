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


# Version check

import sys as _sys
assert _sys.version_info[0] == 2 and _sys.version_info[1] >= 6, \
    "Python 2.6 or a newer 2.x version required."
del _sys


from psirp import libpsirp_py # This is the module created with SWIG
import errno as _errno, os as _os, select as _select, time as _time


# Exceptions/errors

class PubSubException(Exception):
    """Parent class for pub/sub exceptions."""
    pass

class PubSubError(PubSubException, StandardError):
    """Parent class for pub/sub errors."""
    pass


class PubStateError(PubSubError):
    """Parent class for pub/sub state errors."""
    pass

class NotInitializedError(PubStateError):
    """Publication object not initialized."""
    pass

class NotPublishedError(PubStateError):
    """Publication not published."""
    pass


class PubSubNotImplementedError(PubSubError, NotImplementedError):
    """A feature is not implemented, is unsupported, or has been disabled."""
    pass

class NoEventHandlerError(PubSubNotImplementedError):
    """Publication has no event handler"""
    pass


class PubSubIOError(PubSubError, EnvironmentError):
    """Parent class for pub/sub I/O errors."""
    errno_ = _errno.EIO
    
    def __init__(self, err=_errno.EIO, str=""):
        EnvironmentError.__init__(self, err, str)

class NotFoundError(PubSubIOError):
    """Parent class for "not found" errors."""
    pass

class ScopeNotFoundError(NotFoundError):
    """Scope not found."""
    errno_ = _errno.ESRCH
    
    def __init__(self, str=""):
        NotFoundError.__init__(self, self.errno_, str)

class PubNotFoundError(NotFoundError):
    """Publication not found in scope."""
    errno_ = _errno.ENOENT
    
    def __init__(self, str=""):
        NotFoundError.__init__(self, self.errno_, str)


class PubSubTimeoutException(PubSubException):
    """Pub/sub operation timed out."""
    # XXX: This is not classified as an error.
    errno_ = _errno.ETIMEDOUT
    
    def __init__(self, str=""):
        PubSubException.__init__(self, self.errno_, str)

class PubSubStopIteration(PubSubException, StopIteration):
    pass



# Constants

from libpsirp_py import \
    PSIRP_ID_LEN, PSIRP_FID_LEN, \
    NOTE_PUBLISH, NOTE_SUBSCRIBE, NOTE_UNMAP, \
    PS_PUB_SCOPE, PS_PUB_DATA, PS_PUB_VERSION, PS_PUB_PAGE, \
    PS_FLAGS_MASK_NET, PS_FLAGS_MASK_LOCAL, \
    PS_FLAGS_NET_PERSISTENT, PS_FLAGS_NET_FUTUREONLY, \
    PS_FLAGS_LOCAL_FUTUREONLY, PS_FLAGS_LOCAL_LOCALSUB, PS_FLAGS_LOCAL_NETSUB

SID0 = buffer(PSIRP_ID_LEN*'\x00')


# Internal functions

def _create(length):
    v = libpsirp_py.psirp_create(length) # -> (retval, pupb)
    
    if v is None or len(v) < 2 or v[0] != 0 or v[1] is None:
        err = (v[0] if v is not None and len(v) >= 1 else 0)
        raise PubSubIOError(err, "Create failed%s"
                            % (" (kernel module probably not loaded)"
                               if err == -1 else ""))
    
    return v[1] # pupb

def _subscribe(*args):
    v = libpsirp_py.psirp_subscribe_with_flags(*args) # -> (retval, pupb)
    
    if v is None or len(v) < 2 or v[0] != 0 or v[1] is None:
        err = (v[0] if v is not None and len(v) >= 1 else 0)
        if err == PubNotFoundError.errno_:
            raise PubNotFoundError("Publication not found")
        elif err == ScopeNotFoundError.errno_:
            raise ScopeNotFoundError("Scope not found")
        else:
            raise PubSubIOError(err, "Subscribe failed%s"
                                % (" (kernel module probably not loaded)"
                                   if err == -1 else ""))
        
    return v[1] # pupb

def _copybuf(buf):
    return buffer(buf[:])


# Public functions for create, subscribe, publish, and Id conversions

def create(length):
    """Creates a new publication."""
    return Publication._init(_create(length)) # -> Publication
    
def subscribe(sid, rid, flags=0x0000):
    """Subscribes to a publication."""
    return Publication._init(
        _subscribe(sid, rid, flags),
        True) # -> Publication

def subscribe_(sidstr, ridstr, flags=0x0000):
    raise DeprecationWarning("Use sub_s() instead.")

def sub_s(sidstr, ridstr, *args, **kwargs):
    """Subscribes to a publication. Ids are given as hex strings."""
    sid = atoid(sidstr)
    rid = atoid(ridstr)
    return subscribe(sid, rid, *args, **kwargs) # -> Publication

def subscribe_local(sid, rid, flags=PS_FLAGS_LOCAL_LOCALSUB):
    flags |= PS_FLAGS_LOCAL_LOCALSUB
    return subscribe(sid, rid, flags)

def _listen_single(pskq, pub, timeout, exception):
    publ = pskq.listen(1, timeout)
    
    # Error checks
    if len(publ) == 0:
        raise exception(PubSubTimeoutException("Timeout"))
    elif publ[0][1] is not pub:
        raise RuntimeError("Unknown publication returned") # XXX
    
    return publ[0]

def wait_for_rid(sid, rid, t0=None, timeout=None, pskq=None,
                 exception=NotFoundError):
    """Wait until rid appears in scope sid, or until timeout."""

    if t0 is None and timeout is not None:
        t0 = _time.time()
    to = None
    
    if pskq is None:
        pskq = PubSubKQueue()
    
    scope = subscribe_local(sid, sid) # Assume that this scope exists
    pskq.register(scope, True) # Note that scope gets unmapped here
    
    scope_newest = subscribe_local(sid, sid) # Re-subscribe just for sure.
    rids = scope_newest.get_rids(1) # RId 0 is the SId
    rid_count = len(rids)
    if rid in rids:
        # RId found in scope SId
        pskq.unregister(scope)
        return
    del rids
    del scope_newest
    
    try:
        while True:
            if timeout is not None:
                t1 = _time.time()
                td = t1 - t0
                if td > timeout:
                    raise exception(PubSubTimeoutException("Timeout"))
                to = timeout - td
                
            evpub = _listen_single(pskq, scope, to, exception)
            
            scope = evpub[1]
            new_rids = scope.get_rids(rid_count)
            if rid in new_rids:
                # RId found in scope SId
                return
            rid_count += len(new_rids)
    finally:
        pskq.unregister(scope)

def subscribe_sync(sid, rid, timeout=None, flags=0x0000):
    """Synchronous subscribe. (Currently only works with "real" SIds.)"""
    
    t0 = _time.time()
    pskq = PubSubKQueue()
    
    try:
        try:
            try:
                pub = subscribe(sid, rid, flags)
                
                if not (flags & PS_FLAGS_LOCAL_FUTUREONLY):            
                    return pub
            
            except ScopeNotFoundError:
                # The scope doesn't yet exist locally. Subscribe to
                # Scope 0 first (we assume that it always exists), and
                # see if the new scope appears.
                wait_for_rid(SID0, sid, t0, timeout, pskq,
                             ScopeNotFoundError)
                
                # Sub-scope found in given scope;
                # try to subscribe to the publication;
                # goes to outer except if fails.
                return subscribe_local(sid, rid, flags)
        
        except PubNotFoundError:
            # The scope seems to exist locally, but the publication is
            # not in it. Subscribe to the scope, and see if the
            # publication appears.
            wait_for_rid(sid, rid, t0, timeout, pskq,
                         PubNotFoundError)
            return subscribe_local(sid, rid, flags)
        
        # Existing version is to be ignored.
        current_version_index = pub.version_index
        pskq.register(pub, True)
        try:
            # A new version might have been published right before event
            # registration, so we re-subscribe, just for sure.
            pub_newest = subscribe_local(sid, rid)
            if pub_newest.version_index <= current_version_index:
                # No newer version has become available
                del pub_newest
                raise PubNotFoundError() # Caught right below
            del pub_newest
        except NotFoundError:
            # Wait for next publication update
            to = None
            if timeout is not None:
                t1 = _time.time()
                td = t1 - t0
                if td > timeout:
                    raise PubNotFoundError(PubSubTimeoutException("Timeout"))
                to = timeout - td
            evpub = _listen_single(pskq, pub, to, PubNotFoundError)
            pub = evpub[1]
        pskq.unregister(pub)
        pub.saved_version_index = current_version_index
        return pub
        
    finally:
        pskq.close()

def subscribe_sync_local(sid, rid, timeout=None, flags=PS_FLAGS_LOCAL_LOCALSUB):
    flags |= PS_FLAGS_LOCAL_LOCALSUB
    return subscribe_sync(sid, rid, timeout, flags)

def subscribe_sync_(sidstr, ridstr, timeout=None, flags=0x0000):
    raise DeprecationWarning("Use sub_sync_s() instead.")

def sub_sync_s(sidstr, ridstr, *args, **kwargs):
    """Synchronous subscribe. Ids are given as hex strings."""
    sid = atoid(sidstr)
    rid = atoid(ridstr)
    return subscribe_sync(sid, rid, *args, **kwargs) # -> Publication

def publish(sid, rid, pub):
    """Publishes a publication. Same as calling pub.publish(sid, rid)."""
    pub.publish(sid, rid)

def publish_(sidstr, ridstr, pub):
    raise DeprecationWarning("Use pub_s() instead.")

def pub_s(sidstr, ridstr, *args, **kwargs):
    """Publishes a publication. Ids are given as hex strings."""
    publish(sidstr, ridstr, *args, **kwargs)

def atoid(a):
    """Hex string to binary identifier conversion."""
    return buffer(libpsirp_py.psirp_py_atoid(a))

def idtoa(id):
    """Binary identifier to hex string conversion."""
    return libpsirp_py.psirp_idtoa(id)

def idstoa(sid, rid):
    """Binary identifier to hex string conversion."""
    return libpsirp_py.psirp_idstoa(sid, rid)

def idcmp(id1, id2):
    """Compare two identifiers for equality.
    Returns 0 if the identifiers are equal."""
    return libpsirp_py.psirp_idcmp(id1, id2)


# Publication objects

class Publication(object):
    
    """Publication object.
    
    Important notice:
    
    If references to binary data (RIds, buffers, etc.) are stored in
    variables, the underlying data may get unmapped from the
    application's memory space when the publication object is garbage
    collected, or when a new version is acquired via the kevent
    system. This results in a segmentation fault when the old data is
    accessed. Therefore, any data to be stored for later use must
    either be copied, or then the programmer must ensure that the
    publication object and the specific version are kept in memory for
    as long as the data needs to be accessible.
    """
    
    def __init__(self, pub=None):
        """Should not be called explicitly from external sources."""
        
        if pub is not None:
            raise DeprecationWarning()
        
        self.__pubp = None
        self.__published = False
        self.__free_on_del = False
        
        self.__saved_version_index = None
    
    def __del__(self):
        """Destructor that calls psirp_free() by default."""
        
        if self.__pubp is not None and self.__free_on_del:
#             try:
#                 _os.close(libpsirp_py.psirp_pub_fd(self.__pubp))
#             except:
#                 pass
            libpsirp_py.psirp_free(self.__pubp)
            self.__pubp = None
            self.__free_on_del = False
    
    @classmethod
    def _init(cls, pubp, published=False, free_on_del=True):
        pub_type = libpsirp_py.psirp_py_type(pubp)
        if pub_type in _PUB_CLASSES:
            pub_cls = _PUB_CLASSES[pub_type]
        else:
            raise PubSubError("Bad publication type (%d)" % pub_type)
        
        publication = pub_cls() # -> Publication
        publication.__pubp = pubp
        publication.__published = published
        publication.__free_on_del = free_on_del
        
        if published and not isinstance(publication, VersionPublication):
            publication.__saved_version_index = publication.version_index - 1
        
        return publication
    
    @staticmethod
    def _publish(sid, rid, pubp):
        v = libpsirp_py.psirp_publish(sid, rid, pubp);  # -> retval
        
        if v != 0:
            raise PubSubIOError(v, "Publish failed")

    def _checkinit(self):
        if self.__pubp is None:
            raise NotInitializedError()
    
    def _checkpub(self):
        if not self.__published:
            raise NotPublishedError("Publication not yet published")
    
    def _checkinitpub(self):
        if self.__pubp is None:
            raise NotInitializedError()
        if not self.__published:
            raise NotPublishedError("Publication not yet published")
    
    @classmethod
    def from_pubp(cls, pubp, published=False, free_on_del=False):
        """Form a Publication object from a pointer."""
        return cls._init(pubp, published, free_on_del)

    def resubscribe(self):
        """Re-subscribes to the same SId and RId and returns a new object.
        Returns the latest version."""
        # Design choice: we could also replace self.__pubp, but here we
        #                return a new object.
        return subscribe(self.sid, self.rid)
    
    def publish(self, sid=None, rid=None):
        """Publishes the publication."""
        
        self._checkinit()
        
        if sid is None:
            sid = self.sid
        if rid is None:
            rid = self.rid
        
        self._publish(sid, rid, self.__pubp)
        self.__published = True # XXX: ?
        
        if self.__saved_version_index is None \
                and not isinstance(self, VersionPublication):
            self.__saved_version_index = self.version_index
    
    def republish(self):
        """Re-publishes the publication with the same SId and RId."""
        self.publish(None, None)
    
    def publish_(self, sidstr, ridstr):
        raise DeprecationWarning("Use pub_s() instead.")
    
    def pub_s(self, sidstr, ridstr):
        """Publishes the publication. Ids are given as hex strings."""
        
        sid = atoid(sidstr)
        rid = atoid(ridstr)
        return self.publish(sid, rid)
    
    @property
    def pubp(self):
        """Pointer to the underlying psirp_pub_t structure."""
        self._checkinit()
        return self.__pubp
    
    @property
    def datap(self):
        """Pointer to the underlying data."""
        self._checkinit()
        return libpsirp_py.psirp_pub_data(self.__pubp)
    
    @property
    def buffer(self):
        """Get publication data as a read-write buffer."""
        # XXX: A new buffer object is created every time this member
        #      is accessed, which could lead to inefficient code. On
        #      the other hand, replacing it with, e.g., a get_buffer()
        #      function would easily lead to either ugly code, or code
        #      that causes a segmentation fault when the publication
        #      has been freed but the buffer object still exists.
        self._checkinit()
        return libpsirp_py.psirp_py_buffer(self.__pubp)
        
    @property
    def len(self):
        """Publication length."""
        self._checkinit()
        return libpsirp_py.psirp_pub_data_len(self.__pubp)
    
    @property
    def sid(self):
        """Scope identifier (SId)."""
        self._checkinitpub()
        return libpsirp_py.psirp_pub_sid(self.__pubp)
    
    @property
    def rid(self):
        """Rendezvous identifier (RId)."""
        self._checkinitpub()
        return libpsirp_py.psirp_pub_rid(self.__pubp)
    
    @property
    def vrid(self):
        """Current version-RId."""
        self._checkinitpub()      
        return libpsirp_py.psirp_pub_current_version(self.__pubp)
    
    @property
    def version_index(self):
        """Local index of current version."""
        self._checkinitpub()
        return libpsirp_py.psirp_pub_current_version_index(self.__pubp)
    
    @property
    def version_count(self):
        """Total number of locally stored versions."""
        self._checkinitpub()
        return libpsirp_py.psirp_pub_version_count(self.__pubp)
    
    def get_vrids(self, index=0):
        """List of version-RIds."""
        
        self._checkinitpub()
        vrids = libpsirp_py.psirp_py_pub_get_vrids(self.__pubp, index)
        if vrids is None:
            raise PubSubError()
        return vrids
    
    @property
    def fd(self):
        """File descriptor for kevents."""
        self._checkinitpub()
        return libpsirp_py.psirp_pub_fd(self.__pubp)
    
    @property # XXX: Make settable?
    def type(self):
        """Publication type."""
        self._checkinit()
        return libpsirp_py.psirp_py_type(self.__pubp)
    
    @property
    def addr(self):
        """Publication memory address for kevents."""
        self._checkinit() # XXX: initpub?
        # XXXXXX: Return a 32-bit address that can be used as udata in
        #         Python's kevent implementation.
        return int(int(self.__pubp) & ~0x800000000)
    
    @property
    def ridstr(self):
        """RId as a hexadecimal string."""
        return libpsirp_py.psirp_idtoa(self.rid)
    
    @property
    def sidstr(self):
        """SId as a hexadecimal string."""
        return libpsirp_py.psirp_idtoa(self.sid)
    
    @property
    def vridstr(self):
        """Version-RId as a hexadecimal string."""
        return libpsirp_py.psirp_idtoa(self.vrid)
    
    def handle_event(self, event, pub):
        """Event handler function. Abstract by default."""
        raise NoEventHandlerError()
    
    @property
    def saved_version_index(self):
        """Last seen version index.
        Initially set to the current version, but can be updated
        manually, or with the get_versions_since_saved_index()
        function. publish() also updates the value, unless it has
        already been set before."""
        return self.__saved_version_index
    
    @saved_version_index.setter
    def saved_version_index(self, value):
        self.__saved_version_index = value
    
    def get_versions_since_saved_index(self):
        """Returns a generator for the versions between the saved index
        and the current index."""
        first_index = self.__saved_version_index+1
        last_index  = self.version_index
        versions = subscribe_versions(self,
                                      first_index,
                                      last_index)
        self.__saved_version_index = last_index
        return versions
    
    def __str__(self):
        if not self.__published:
            return repr(self)
        return "<%s SId=%s RId=%s vRId=%s len=%d fd=%d>" \
            % (self.__class__.__name__,
               ("" if not isinstance(self, DataPublication) else self.sidstr),
               self.ridstr,
               self.vridstr,
               self.len,
               self.fd)

class DataPublication(Publication):
    pass

class ScopePublication(DataPublication):
    def __init__(self):
        """Should not be called explicitly from external sources."""
        super(type(self), self).__init__()
    
    # New methods and members
    
    @property
    def rid_count(self):
        """Number of RIds in scope."""
        self._checkinitpub()
        return libpsirp_py.psirp_scope_rid_count(self.pubp)
    
    def get_rids(self, index=0):
        """List of RIds in scope."""
        
        self._checkinitpub()
        rids = libpsirp_py.psirp_py_scope_get_rids(self.pubp, index)
        if rids is None:
            raise PubSubError()
        return rids
    
    # Disabled methods and members
    
    def publish(self, sid=None, rid=None):
        """Disabled."""
        raise PubSubNotImplementedError(
            "Scope publication cannot be published")
    # XXX: publish_ and republish?
    
    @property
    def buffer(self):
        """Disabled."""
        raise PubSubNotImplementedError(
            "Raw scope data cannot be accessed")

class VersionPublication(Publication):
    def __init__(self):
        """Should not be called explicitly from external sources."""
        super(type(self), self).__init__()

    # New methods and members
    
    def get_prids(self, index=0):
        """List of page-RIds."""
        
        self._checkinitpub()
        prids = libpsirp_py.psirp_py_version_get_prids(self.pubp, index)
        if prids is None:
            raise PubSubError()
        return prids
    
    # Modified methods and members
    
    @property
    def rid(self):
        """RId of the data publication."""
        return super(type(self), self).sid # The SId is the RId
    
    @property
    def vrid(self):
        """Version-RId of this version."""
        return super(type(self), self).rid # The RId is the version-RId
    
    # Disabled methods and members
    
#     def publish(self, sid=None, rid=None):
#         """Disabled."""
#         raise PubSubNotImplementedError(
#             "Re-publishing a version publication is not supported") # XXX
    
    def republish(self):
        """Disabled."""
        raise PubSubNotImplementedError(
            "Re-publishing a version publication is not supported") # XXX
    
    def resubscribe(self):
        """Resubscribe the same version.""" # (Not very useful)
        return subscribe(self.rid, self.vrid)
    
    @property
    def sid(self):
        """Disabled."""
        raise PubSubNotImplementedError(
            "Version publication does not have a SId")
    
    @property
    def version_index(self):
        """Disabled."""
        raise PubSubNotImplementedError(
            "Version publication does not have versions")

    @property
    def version_count(self):
        """Disabled."""
        raise PubSubNotImplementedError(
            "Version publication does not have versions")
    
    def get_vrids(self):
        """Disabled."""
        raise PubSubNotImplementedError(
            "Version publication does not have versions")

class PagePublication(Publication):
    def __init__(self):
        """Should not be called explicitly from external sources.
        
        WARNING: Page publications might behave strangely in this release.
                 Thus it is not recommended to use them.
        """
        super(type(self), self).__init__()
    

_PUB_CLASSES = {PS_PUB_DATA:    DataPublication,
                PS_PUB_SCOPE:   ScopePublication,
                PS_PUB_VERSION: VersionPublication,
                PS_PUB_PAGE:    PagePublication}


# Pub/sub kqueue

def _default_exception_handler(exception):
    raise exception

class AdvSubDesc(int):
    """Advance Subscription Descriptor."""
    pass

class PubSubKQueue(object):
    """Pub/sub kqueue."""
    def __init__(self, kq=None):
        self.kq = _select.kqueue() if kq is None else kq
        self.pubs = {}
        
        self.adv_subs = {}
        self.asd = AdvSubDesc(0)
    
    def close(self):
        """Close the kqueue."""
        
        self.kq.close()
        self.pubs.clear()
    
    def register(self, pub, update=False): #, unmap=False):
        """Register to kevents for a publication.
        
        Args:
        pub    - publication object
        update - True:  update pub to the latest version when an event occurs
                 False: keep the current version and leave pub untouched
        """
#        unmap  - True:  unmap the old version from our memory space
#                 False: keep the old version mapped
        
        ident = pub.fd
        filter = _select.KQ_FILTER_VNODE
        flags = _select.KQ_EV_ADD | _select.KQ_EV_CLEAR
        fflags = NOTE_PUBLISH
#        if unmap:
#            fflags |= NOTE_UNMAP # XXX: free_on_del?
        data = 0x0
        if update:
            udata = pub.addr
            fflags |= NOTE_UNMAP # XXX
        else:
            udata = 0x0
        
        evf = _select.kevent(ident, filter, flags, fflags, data, udata)
        self.kq.control([evf], 0, None)
        
        self.pubs[ident] = pub
    
    def custom_command(self, ident,
                       filter=_select.KQ_FILTER_VNODE,
                       flags=_select.KQ_EV_ADD|_select.KQ_EV_CLEAR,
                       fflags=0x0,
                       data=0x0,
                       udata=0x0):
        """Register or unregister any kevents on this kqueue."""
        
        evf = _select.kevent(ident, filter, flags, fflags, data, udata)
        self.kq.control([evf], 0, None)
    
    def unregister(self, pub):
        """Unregister a publication."""
        
        ident = pub.fd
        filter = _select.KQ_FILTER_VNODE
        flags = _select.KQ_EV_DELETE
        
        evf = _select.kevent(ident, filter, flags)
        self.kq.control([evf], 0, None)
        
        del self.pubs[ident]
    
    def listen(self, n=1, timeout=None):
        """Listen to kevents.
        
        Args (optional):
        n       - max. number of kevents to return in a list
        timeout - kevent timeout value
        
        Returns:
        List of (event, publication) tuples.
        """
        
        publ = None
        
        try:
            evl = self.kq.control(None, n, timeout) # listen to kevents
            
            if evl is not None:
                publ = []
                for ev in evl:
                    if ev.ident in self.pubs:
                        publ.append((ev, self.pubs[ev.ident]))
                    else:
                        publ.append((ev, None))
                return publ
                
        except (KeyboardInterrupt, SystemExit):
            raise
        except OSError, ose:
            if ose.errno == _errno.EINTR:
                raise KeyboardInterrupt(ose) # XXX
            raise ose
    
    
    def listen_and_handle(self, exc_handler=_default_exception_handler,
                          timeout=None, max_tot_evs=None):
        """Call pub.handle_event(event, pub) for each event.
        
        Args (optional):
        exc_handler - exception handler if a handle_event() call fails
                      (raising StopIteration causes this function to return)
        timeout     - listen timeout value for each listen() call
        max_tot_evs - maximum total number of events to handle before returning
        """
        
        i = 0
        try:
            while True:
                if max_tot_evs is not None and i >= max_tot_evs:
                    raise PubSubStopIteration()
                
                evpubl = self.listen(1, timeout) # Listen to an event
                if len(evpubl) == 0:
                    raise PubSubTimeoutException("Timeout") # Timeout
                for ev, pub in evpubl:
                    try:
                        if max_tot_evs is not None:
                            if i >= max_tot_evs: # Safety check
                                raise PubSubStopIteration()
                            i += 1
                        pub.handle_event(ev, pub) # Call event handler
                    except Exception, e:
                        exc_handler(e) # Call exception handler
        except PubSubStopIteration, si:
            return si
    
    
    def reg_adv_sub_s(self, sidstr, ridstr, *args, **kwargs):
        """Register advance subscription. Ids are given as hex strings."""
        sid = atoid(sidstr)
        rid = atoid(ridstr)
        return self.register_advance_subscription(sid, rid, *args, **kwargs)
    
    @property
    def __next_asd(self):
        self.asd = self.asd.__add__(1)
        return self.asd

    def __get_scope0_evh(self, asd, sid, rid, handle_event, rid_count=1):
        __rid_count = [rid_count]
        
        def scope0_evh(event, scope0):
            # XXX: Check event?
            rids = scope0.get_rids(__rid_count[0])
            __rid_count[0] = len(rids)
            
            if sid in rids:
                scope = subscribe_local(sid, sid)
                self.register(scope, True)
                
                scope_newest = subscribe_local(sid, sid)
                srids = scope_newest.get_rids(1)
                rid_count = len(srids)
                if rid in srids:
                    pub = subscribe_local(sid, rid)
                    ev = _select.kevent(scope.fd, fflags=NOTE_PUBLISH)
                    self.unregister(scope)
                    self.unregister_advance_subscription(asd)
                    pub.saved_version_index = -1
                    return handle_event(ev, pub)
                del scope_newest
                
                self.unregister(scope0)
                self.adv_subs[asd] = scope
                scope.handle_event = \
                    self.__get_scope_evh(asd, sid, rid, handle_event, rid_count)
        
        return scope0_evh
    
    def __get_scope_evh(self, asd, sid, rid, handle_event, rid_count=1):
        __rid_count = [rid_count]
        
        def scope_evh(event, scope):
            # XXX: Check event?
            rids = scope.get_rids(__rid_count[0])
            __rid_count[0] = len(rids)
            
            if rid in rids:
                pub = subscribe_local(sid, rid)
                ev = _select.kevent(pub.fd, fflags=NOTE_PUBLISH)
                self.unregister_advance_subscription(asd)
                pub.saved_version_index = -1
                return handle_event(ev, pub)
        
        return scope_evh
    
    def __get_pub_evh(self, asd, handle_event):
        def pub_evh(event, pub):
            # XXX: Check event?
            self.unregister_advance_subscription(asd)
            return handle_event(event, pub)
        return pub_evh
    
    def unregister_advance_subscription(self, adv_sub_desc):
        if adv_sub_desc in self.adv_subs:
            pub = self.adv_subs[adv_sub_desc] # Old Pub / Scope / Scope 0
            self.unregister(pub)
            del self.adv_subs[adv_sub_desc]
    
    def register_advance_subscription(self, sid, rid, flags, handle_event):
        """Subscribe to a publication even if does not exists locally.
        
        If the publication already exists, it is returned. If not, an
        advance subscription desciptor is returned, and handle_event
        can be called in a listen()-loop when the publication becomes
        available.
        
        Note:
        The interpretation of flags can appear a bit cumbersome; they
        only apply to the initial subscription that is done when this
        function is called - not later, when the publication becomes
        available.
        If PS_FLAGS_LOCAL_FUTUREONLY is set, we wait for a future
        version as if the publication would not yet exist (not very
        useful; consider just registering instead).
        
        Args:
        sid          - SId
        rid          - RId
        flags        - subscription flags
        handle_event - initial event handler
        """
        try:
            try:
                pub = subscribe(sid, rid, flags)
                
                if (flags & PS_FLAGS_LOCAL_FUTUREONLY):
                    current_version_index = pub.version_index
                    self.register(pub, True)
                    # XXX: Timing. Resubscribe after registration?
                    asd = self.__next_asd
                    self.adv_subs[asd] = pub
                    pub.handle_event = self.__get_pub_evh(asd, handle_event)
                    pub.saved_version_index = current_version_index
                    return asd
                
                return pub
                
            except ScopeNotFoundError:
                # The scope doesn't yet exist locally.
                # Subscribe to Scope 0 first.
                try:
                    scope0 = subscribe_local(SID0, SID0)
                except NotFoundError:
                    raise ScopeNotFoundError("Scope 0 does not exist")

                self.register(scope0, True)

                scope0_newest = subscribe_local(SID0, SID0)
                rids = scope0_newest.get_rids(1) # RId 0 is the SId
                rid_count = len(rids)
                if sid in rids:
                    # SId found in scope SId
                    self.unregister(scope0)
                    raise PubNotFoundError()
                del scope0_newest
                
                asd = self.__next_asd
                self.adv_subs[asd] = scope0
                scope0.handle_event = \
                    self.__get_scope0_evh(asd, sid, rid, handle_event,
                                          rid_count)
                return asd
        
        except PubNotFoundError:
            # The scope seems to exist locally, but the publication is
            # not in it. Subscribe to the scope, and see if the
            # publication appears.
            scope = subscribe_local(sid, sid)            
            self.register(scope, True)
            # XXX: Timing. Resubscribe after registration?
            asd = self.__next_asd
            self.adv_subs[asd] = scope
            scope.handle_event = \
                self.__get_scope_evh(asd, sid, rid, handle_event)
            return asd
        

def subscribe_versions(pub, start_index, stop_index=None):
    """Subscribes to the specified range of versions.
    
    Args:
    pub         - publication object
    start_index - index of first version to include
    stop_index  - index of last version to include (default: last index)
    
    Usage scenario:
    If a publication is updated multiple times during the time when a kevent
    is being processed, only one kevent is returned, and the publication data
    is set to point to the latest version. With this function, the "missed"
    intermediate versions can be acquired conveniently if they're needed.
    
    Example:
    subscribe_versions(pub, previous_index+1, pub.version_index-1)
    """
    
    vcount = pub.version_count
    if stop_index is None:
        stop_index = vcount-1
    if stop_index >= vcount or start_index < 0 or start_index > stop_index:
        raise IndexError("Version indexes %d..%d out of range"
                         % (start_index, stop_index))
    
    rid = pub.rid
    vrids = pub.get_vrids(start_index)
    n = (stop_index - start_index) + 1
    
    for i in xrange(n):
        yield subscribe(rid, vrids[i])

def subscribe_versions_as_list(*args, **kwargs):
    vpubs = []
    for vpub in subscribe_versions(*args, **kwargs):
        vpubs.append(vpub)
    return vpubs
