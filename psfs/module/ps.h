/*
 * Copyright (C) 2009-2010, Oy L M Ericsson Ab, NomadicLab.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of
 * the BSD license.
 *
 * See LICENSE and COPYING for more details.
 */

#ifndef _PS_H
#define _PS_H

/* User space applications
 * 
 * Required definitions:
 * - kevent flags
 * - ps_pub (user space view) && accessors
 *
 * User space libraries
 *
 * Required definitions:
 * - kevent flags
 * - ps_pub (almost full kernel view [includes meta data])
 * - syscalls && args
 * - 
 *
 * Kernel
 *
 * Required defintions:
 * - Everything but...
 *   - user space (re)definitions
 *
 */

/*
 * The system call module name.  Shared between user level and library.
 *
 * If you change this, be sure to change SYSCALL_MODULE definition in
 * the end of ps_syscall.c
 */

#define PS_SYSCALL_MODULE       ps_syscall
#if __FreeBSD_version < 801000
#define PS_SYSCALL_MODULE_NAME "ps_syscall"
#else
#define PS_SYSCALL_MODULE_NAME "sys/ps_syscall"
#endif

/*
 * UID and GID for versions and pages, which are shared between publications
 * therefore not really "owned" by anybody
 */
#ifndef UID_NOBODY
#define UID_NOBODY 65534
#endif
#ifndef GID_NOBODY
#define GID_NOBODY 65534
#endif


/*
 * New VNODE kevent types.  NOTE_PUBLISH returns publish events, either on
 * a publication vnode, in which case udata points to ps_pub_t, or
 * on the root vnode, in which case udata points to ps_scope_knote.
 * NOTE_SUBSCRIBE is less well defined at this point, but can be used
 * at least on the root vnode, using ps_scope_knote.
 * 
 * NOTE_UNMAP is not really a traditional kevent, but a shorthand to
 * unmap previous publication version at kevent(2) call time.
 */
#define NOTE_PUBLISH    0x0100
#define NOTE_SUBSCRIBE  0x0200
#define NOTE_UNMAP      0x0400

/* Identifiers */

#define PSIRP_ID_LEN    32
#define PSIRP_FID_LEN   PSIRP_ID_LEN

struct psirp_id {
    u_int8_t id[PSIRP_ID_LEN]; /**< Common ID structure (P:L, Scope, etc) */
};

typedef struct psirp_id psirp_id_t, psirp_fid_t;

/* XXXX: Magic prefixes for special RIds */
#define PSIRP_VRID_PREFIX  0x006e6f6973726556 /* "Version" */
#define PSIRP_PRID_PREFIX          0x65676150 /* "Page"    */

/* XXX: Should use different magic numbers instead of the enum */
enum ps_pub_type { PS_PUB_UNINITIALISED=0, PS_PUB_UNKNOWN, 
		   PS_PUB_SCOPE, PS_PUB_DATA, PS_PUB_VERSION, PS_PUB_PAGE,
                   PS_PUB_TYPE_COUNT };
#define PS_PUB_TYPE(meta)       ((meta)->pm_type)
#define PS_PUB_MUTABLE(meta)    ((meta)->pm_type < PS_PUB_VERSION)
#define PS_PUB_CHECK_TYPE(meta) (PS_PUB_TYPE(meta) > PS_PUB_UNINITIALISED && PS_PUB_TYPE(meta) < PS_PUB_TYPE_COUNT)

#ifdef PS_META_BF
#define PS_META_BF_LEN PSIRP_ID_LEN
struct ps_meta_bf {
    u_int8_t bf[PS_META_BF_LEN];
};
typedef struct ps_meta_bf ps_meta_bf_t;
#define PS_META_BF_K 4
#endif

struct ps_meta_hdr {
    psirp_id_t        	     _pm_h_magic;     /* Metadata type */
    psirp_id_t               _pm_h_id;	      /* RID for this publication/version/page */
    enum ps_pub_type         _pm_h_type;      /* XXX: To be merger with pm_magic? */
    off_t                    _pm_h_size;      /* Bytes in the data vm_object */
#ifdef PS_META_BF
    union {
        ps_meta_bf_t         _pm_bf_u_idh;     /* Pre-hashed identifier */
        ps_meta_bf_t         _pm_bf_u_sub_obj; /* Could be used for lookups */
    } _pm_h_bf_u;
#endif
    union {
	struct {
	    int              _pm_m_vers_count;
	    struct mtx      *_pm_m_interlock;
	} _pm_u_mutable;
	struct {
	    int              _pm_s_page_count; /* Fixed at creation time */
	} _pm_u_static;
    } _pm_h_u;
};
#define PS_META_SUB_OBJECT_COUNT ((PAGE_SIZE - sizeof(struct ps_meta_hdr)) / sizeof(psirp_id_t))
struct ps_meta {
    struct ps_meta_hdr       _pm_h;
    psirp_id_t               pm_sub_object[PS_META_SUB_OBJECT_COUNT];
};
typedef struct ps_meta *ps_meta_t;
#define pm_magic      _pm_h._pm_h_magic
#define pm_type       _pm_h._pm_h_type
#define pm_id         _pm_h._pm_h_id
#define pm_size       _pm_h._pm_h_size
#ifdef PS_META_BF
#define pm_bf_idh     _pm_h._pm_h_bf_u._pm_bf_u_idh
#define pm_bf_sub_obj _pm_h._pm_h_bf_u._pm_bf_u_sub_obj
#endif
#define pm_interlock  _pm_h._pm_h_u._pm_u_mutable._pm_m_interlock
#define pm_vers_count _pm_h._pm_h_u._pm_u_mutable._pm_m_vers_count
#define pm_page_count _pm_h._pm_h_u._pm_u_static._pm_s_page_count

struct psfs_pub;


/*
 * Subscription flags. Mainly related to "network" subscriptions.
 */
typedef u_int16_t ps_flags_t;

/* Flags that affect network pub/sub behaviour, also in other nodes. */
#define PS_FLAGS_MASK_NET         0x00ff
/* Flags that affect node-local pub/sub behaviour, incl. local rendezvous. */
#define PS_FLAGS_MASK_LOCAL       0xff00

/* Subscribe to all future versions, and the current one by default. */
#define PS_FLAGS_NET_PERSISTENT   0x0001
/* Do not return the current version from the network. */
#define PS_FLAGS_NET_FUTUREONLY   0x0002
    
#if 0 /* Not used yet. */
/* Subscribe to all future versions, and the current one by default. */
#define PS_FLAGS_LOCAL_PERSISTENT 0x0100
#endif
/* Do not return the current version when subscribing synchronously. */
#define PS_FLAGS_LOCAL_FUTUREONLY 0x0200
/* Trigger a network subscription even if a version exists locally. */
#define PS_FLAGS_LOCAL_NETSUB     0x0400
/* Do not trigger a network subscription. */
#define PS_FLAGS_LOCAL_LOCALSUB   0x0800


#if defined(_LIBPSIRP) || defined(_KERNEL)
/*
 * Library/kernel interface.  Opaque to the user apps.
 */
struct psfs_pub {
    ps_meta_t    pub_meta;		/* Pointer to the local metadata */
    u_int64_t    pub_mlen;		/* Length of the metadata == PSFS_MD_SIZE */
    caddr_t      pub_data;		/* Pointer to the actual data */
    u_int64_t    pub_dlen;		/* Length of the actual data */
    int          pub_fd;                /* Dir fd, maintained by the library */
    int          pub_vidx;              /* Version index */
    psirp_id_t   pub_sid;               /* SID used when subscribed/published*/
  
};

typedef enum ps_vmo { VMO_META, VMO_DATA, VMO_NUM } ps_vmo_t;

#endif

typedef struct psfs_pub psfs_pub_t, *psirp_pub_t;

#define PSFS_PUB_META(p)     ((p)->pub_meta)
#define PSFS_PUB_META_LEN(p) ((p)->pub_mlen)
#define PSFS_PUB_DATA(p)     ((p)->pub_data)
#define PSFS_PUB_DATA_LEN(p) ((p)->pub_dlen)
#define PSFS_PUB_FD(p)       ((p)->pub_fd)


#endif /* _PS_H */
