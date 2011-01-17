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

#ifndef _PSIRPD_OUT_Q_H
#define _PSIRPD_OUT_Q_H

/** Output queue list item */
struct out_q_list_item {
    STAILQ_ENTRY(out_q_list_item) entries;
    psirp_fid_t      fid;      /**< Forwarding ID */
    psirp_id_t       rid;      /**< Rendezvous ID */
    psirp_id_t       vrid;     /**< Version-RID */
    psirp_id_t       sid;      /**< Scope ID */
    psirp_pub_t     *pubp;
    int             *countp;
    u_int64_t        seqnum;
};
typedef struct out_q_list_item out_q_list_item_t;

psirp_error_t psirpd_out_q_init(void);
void psirpd_out_q_cleanup(void);
out_q_list_item_t* psirpd_out_q_create_item(psirp_id_t*,
                                            psirp_id_t*,
                                            psirp_id_t*,
					    psirp_fid_t*,
					    psirp_pub_t*,
					    int *,
                                            u_int64_t);
void psirpd_out_q_add_item(out_q_list_item_t*);
psirp_error_t psirpd_out_q_send(void);
struct timespec* psirpd_out_q_next_timeout(struct timespec*);

#endif /* _PSIRPD_OUT_Q_H */
