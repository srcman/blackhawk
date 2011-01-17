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


#ifndef _PSIRPD_RZV_H
#define _PSIRPD_RZV_H

psirp_error_t psirpd_rzv_init(u_int8_t);
void psirpd_rzv_cleanup(void);
psirp_error_t psirpd_rzv_create_rid(psirp_id_t*);
psirp_error_t psirpd_rzv_rcv_datachunk(pkt_ctx_t*);
psirp_error_t psirpd_rzv_rcv_subscribe_metadata(pkt_ctx_t*);
psirp_error_t psirpd_rzv_snd_subscribe(pkt_ctx_t*);
psirp_error_t psirpd_rzv_rcv_subscribe_data(pkt_ctx_t*);
psirp_error_t psirpd_rzv_rcv_metadata(pkt_ctx_t*);
psirp_error_t psirpd_rzv_snd_metadata(pkt_ctx_t*);

#endif /* PSIRPD_RZV_H */
