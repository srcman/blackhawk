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
 * Scope data structure, consisting of pages.
 *
 * There are two types of pages:  Index pages and Data pages.
 * An index page contains pointers to data pages.
 * A data page has a header and up to ~120 RIDs.
 */

#define PS_SCOPE_BF_LEN 32
struct ps_scope_bf {
    u_int8_t bf[PS_SCOPE_BF_LEN];
};
typedef struct ps_scope_bf ps_scope_bf_t;
#define PS_SCOPE_BF_K 4

struct ps_scope_page_hdr {
    psirp_id_t    _sph_magic;
    ps_scope_bf_t _sph_bf;
    int32_t       _sph_id_count;
};

struct ps_scope_idx_entry {
    psirp_id_t ie_first_id;
    psirp_id_t ie_page_rid;
};

#define PS_SCOPE_IDX_NELEM  \
  ((PAGE_SIZE - sizeof(struct ps_scope_page_hdr)) / sizeof(struct ps_scope_idx_entry))

struct ps_scope_idx_page {
    struct ps_scope_page_hdr   _sip_hdr;
    struct ps_scope_idx_entry   sip_entries[PS_SCOPE_IDX_NELEM];
};

#define PS_SCOPE_DAT_NELEM \
  ((PAGE_SIZE - sizeof(struct ps_scope_page_hdr)) / sizeof(psirp_id_t))

struct ps_scope_dat_page {
    struct ps_scope_page_hdr _sdp_hdr;
    ps_scope_bf_t             sdp_bf;
    psirp_id_t                sdp_entries[PS_SCOPE_DAT_NELEM];
};

#define sdp_magic    _sdp_hdr._sph_magic
#define sdp_bf       _sdp_hdr._sph_bf
#define sdp_id_count _sdp_hdr._sph_id_count

#ifdef _KERNEL

typedef int (*ps_scope_iterator)(void *arg, psirp_id_t *entry);

int ps_scope_get_rid(ps_pubi_t pi, psirp_id_t *ridp, off_t *idxp);
int ps_scope_get_rid_count(ps_pubi_t pi, off_t *countp, boolean_t only_sids);
int ps_scope_iterate(ps_pubi_t pi, ps_scope_iterator i, off_t start, off_t count, 
		     void *arg, int *eofflag);

int ps_scope_verify_format(vm_object_t data);

#endif
