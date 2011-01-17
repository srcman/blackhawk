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


#ifndef _PSIRPD_FWD_BF_H
#define _PSIRPD_FWD_BF_H

struct pkt_ctx;

psirp_error_t psirpd_fwd_bf_init(void);
void psirpd_fwd_bf_cleanup(void);
psirp_error_t psirpd_fwd_add_bf_to_iface(if_list_item_t*);
psirp_error_t psirpd_fwd_bf_handler(struct pkt_ctx*);
psirp_error_t psirpd_fwd_bf_out(struct pkt_ctx*);
psirp_error_t psirpd_fwd_fidcollect(struct pkt_ctx*);

#endif /* PSIRPD_FWD_BF_H */
