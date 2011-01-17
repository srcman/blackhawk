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

#ifndef _PS_SYSCALL_H
#define _PS_SYSCALL_H

/* 
 * Use map entry flag to separate publications from other entries.
 * MAP_ENTRY_BEHAV_RESERVED is defined in sys/vm_map.h
 */
#define MAP_ENTRY_PUBLICATION MAP_ENTRY_BEHAV_RESERVED

/*
 * Use extra memory pages to store local metadata.
 * This is used to store e.g. RId (also for metadata publications...)
 */
#define PS_MD_PAGES    1
#define PS_MD_SIZE     (PS_MD_PAGES * PAGE_SIZE)

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/*
 * Syscall operation codes.
 */
#define PS_SYSCALL_NOP 0          /**< No-op */
#define PS_SYSCALL_STA 1          /**< Print stats */
#define PS_SYSCALL_CRE 2          /**< Create */
#define PS_SYSCALL_PUB 3          /**< Publish */
#define PS_SYSCALL_SUB 4          /**< Subscribe */

/*
 * Flags.
 */
#define PS_SYSCALL_USE_SID      0x00000001 /**< SID defined. */
#define PS_SYSCALL_USE_RID      0x00000002 /**< RID defined. */
#define PS_SYSCALL_SUB_METADATA 0x00000004 /**< Subscribe metadata only. */

/*
 * Sizes of key elements, as supported by the kernel
 */
/**
 * Argument going to syscall handler.
 */
struct ps_syscall_sc_arg {
    void *p;              /**< Pointer to struct ps_syscall_arg. */
};

typedef struct ps_syscall_sc_arg ps_syscall_sc_arg_t;

/**
 * Argument copied from userspace to kernel in syscall handler.
 */
typedef struct ps_syscall_obj {
    caddr_t     so_addr;     /**< User space address. */
    u_int64_t   so_len;      /**< Length of memory. */
} ps_sysobj_t;    

struct ps_syscall_arg {
    u_int8_t    a_op;            /**< Operation code. */
    u_int32_t   a_retval;        /**< Return value; FD. */
    psirp_id_t  a_sid;	         /**< SId for pub/sub ops. */
    psirp_id_t  a_rid;	         /**< RId for pub/sub ops. */
    ps_sysobj_t a_obj[VMO_NUM];  /**< Metadata and data objects. */
#define a_meta a_obj[VMO_META].so_addr
#define a_mlen a_obj[VMO_META].so_len
#define a_data a_obj[VMO_DATA].so_addr
#define a_dlen a_obj[VMO_DATA].so_len
    int         a_vridx;         /**< Version RID index. */
    ps_flags_t  a_flags;         /**< Flags. */
    caddr_t     a_retbuf;        /**< Application allocated feedback buffer.*/
    u_int64_t   a_retbuf_len;    /**< Make a guess. */
};

typedef struct ps_syscall_arg ps_syscall_arg_t;

/**
 * Local metadata structure. Used to transmit metadata to library
 * and kernel.  
 *
 * XXX: Needs to be updated
 */

/*
 * Userspace handle to a publication.  Keeps track of the memory offsets and sizes.
 * 
 * Use macros to access.  May change as the userspace-kernel interface changes.
 */

 


#ifdef _KERNEL
int ps_kern_publish(struct thread *td, psirp_id_t sid, psirp_id_t rid, 
		    vm_object_t dobj, vm_ooffset_t dlen, vm_ooffset_t doff,
		    vm_object_t *mobjp, vm_ooffset_t mlen,
		    struct vnode **vpp, int *vindex);
#endif

#endif /* _PS_SYSCALL_H */
