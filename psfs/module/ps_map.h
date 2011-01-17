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

/*
 * Memory mapping interface: psfs_mmap.c
 */

int ps_mfind (struct thread *td, vm_offset_t addr,  vm_ooffset_t size, 
	      vm_object_t *objectp, vm_ooffset_t *offp);
int ps_mmap  (struct thread *td, vm_offset_t *addr, vm_ooffset_t size,
	      vm_prot_t prot, vm_prot_t maxprot, int flags,
	      vm_object_t object, vm_ooffset_t foff);
int ps_mcow  (struct thread *td, vm_offset_t addr,  vm_ooffset_t size);
int ps_munmap(struct thread *td, vm_offset_t addr,  vm_ooffset_t size);

int ps_kmap_page(vm_object_t object, vm_pindex_t pindex, vm_page_t *pagep);
int ps_kunmap_page(vm_object_t object, vm_page_t page, boolean_t written);

