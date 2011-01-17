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

#ifndef PSIRPD_PACKET_H_
#define PSIRPD_PACKET_H_

struct pkt_ctx;
struct pkt_handler;

struct pkt_call {
    psirp_error_t (*handler)(struct pkt_ctx*);
    struct pkt_handler* (*exception)(struct pkt_ctx*, psirp_error_t);
};
typedef struct pkt_call pkt_call_t;

struct pkt_handler {
    char name[256];  /**< Printable name of the state */
    pkt_call_t call[];
};
typedef struct pkt_handler pkt_handler_t; 

struct psirpd_hdrs;
struct psirpd_hdrs_fwhdr;
struct psirpd_hdrs_rzvhdr;
struct psirpd_hdrs_metadata;
struct psirpd_hdrs_pla;


/** State machine context structure for packet handling */
struct pkt_ctx {
    u_int32_t ctx_id;                 /**< Packet context ID */

    if_list_item_t *iface_in;         /**< inteface in */
    u_int32_t iface_out_cnt;          /**< number of interfaces out */
    if_list_item_t *iface_out[PSIRP_MAX_NO_IFACES]; /**< interfaces out */

#if 0
    pub_list_item_t *pub;             /**< pointer to an item in pub. list */
#endif
    
    u_int8_t *pkt;                    /**< beginning of the packet */
    u_int8_t *offset;                 /**< pointer to the end of the data */
    u_int32_t pkt_len;                /**< length of the reserved buffer */

    struct psirpd_hdrs          *prev_hdr; /**< pointer to previous header */

    struct psirpd_hdrs_fwhdr    *fwd_hdr;  /**< forwarding header */
    struct psirpd_hdrs_rzvhdr   *rzv_hdr;  /**< rendezvous header */
    struct psirpd_hdrs_pla      *pla_hdr;  /**< PLA header */
    struct psirpd_hdrs_metadata *md_hdr;   /**< metadata header */

    u_int8_t *payload;                /**< payload */

    pkt_handler_t *handler;           /**< handler functions */
    /** The recently called function in the handler */
    int handler_call_cnt;            
};

typedef struct pkt_ctx pkt_ctx_t;



psirp_error_t psirpd_packet_init(void);
void psirpd_packet_cleanup(void);
psirp_error_t psirpd_packet_register(psirp_error_t (*call)(pkt_ctx_t*));
psirp_error_t psirpd_packet_add_iface(if_list_item_t*);
pkt_ctx_t* psirpd_packet_create_ctx_out(pkt_handler_t*);
pkt_ctx_t* psirpd_packet_create_ctx_in(u_int8_t*,
                                       u_int32_t,
                                       if_list_item_t*);
void psirpd_packet_free_ctx_out(pkt_ctx_t*);
void psirpd_packet_free_ctx_in(pkt_ctx_t*);
#if 0
void psirpd_packet_init_hdr(pkt_ctx_t*, psirpd_hdrs_t*, u_int32_t);
psirp_error_t psirpd_packet_preset_hdrs(pkt_ctx_t*, 
                                        u_int32_t,
                                        psirp_fid_t*,
                                        psirp_id_t*,
                                        psirp_id_t*,
                                        psirp_id_t*,
                                        psirp_fid_t*);
#endif
psirp_error_t psirpd_packet_preparse(pkt_ctx_t*);

psirp_error_t psirpd_packet_state_machine(pkt_ctx_t*);
psirp_error_t psirpd_packet_in( u_int8_t*, u_int32_t, if_list_item_t*);
psirp_error_t psirpd_packet_out_metadata(psirp_id_t *,
                                         psirp_id_t *,
                                         psirp_id_t *,
                                         psirp_fid_t *,
					 u_int64_t);
psirp_error_t psirpd_packet_out_submetadata(psirp_id_t *, psirp_id_t *,
                                            psirp_id_t *,
					    psirp_fid_t *,
                                            ps_flags_t);
psirp_error_t psirpd_packet_out_subdata(psirp_id_t *, psirp_id_t *,
                                        psirp_id_t *,
					psirp_fid_t *, psirp_fid_t *,
					u_int8_t);
psirp_error_t psirpd_packet_out_data(u_int8_t*, 
				     int,
				     struct out_q_list_item*);
psirp_error_t psirpd_packet_out_queuechunks(psirp_id_t *,
                                            psirp_id_t *,
                                            psirp_id_t *,
                                            psirp_fid_t *);


/* for easier debugging */
char *psirpd_packet_get_headers(pkt_ctx_t *ctx);


#endif /* PSIRPD_PACKET_H_ */
