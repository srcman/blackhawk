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

#ifndef _PSIRPD_SEC_PLA_H
#define _PSIRPD_SEC_PLA_H

struct pkt_ctx;

#ifndef PSIRP_PLA
struct pla_hdr
{
    uint8_t next_header_type;

#define PLA_PUBKEY_LEN  (168/8)
    char implicit_certificate[PLA_PUBKEY_LEN];
    char ttp_public_key[PLA_PUBKEY_LEN];
#define PLA_SIG_LEN     (328/8)
    char signature[PLA_SIG_LEN];

    uint32_t ttp_identity;
    uint32_t ttp_not_before_time;
    uint32_t ttp_not_after_time;
    uint8_t ttp_rights;
    uint8_t ttp_deleg_rights;

    uint32_t timestamp;
    uint64_t sequence_number;
};

#define PLA_SIG_OK          0x1
#endif

struct psirpd_hdrs_pla {
    u_int8_t  hdr_type;
    u_int8_t  nxt_hdr;
    struct pla_hdr pla_hdr_lib;
} __attribute__((__packed__));
typedef struct psirpd_hdrs_pla psirpd_hdrs_pla_t;

psirp_error_t psirpd_sec_pla_init(void);
void psirpd_sec_pla_cleanup(void);
psirp_error_t psirpd_sec_pla_get_rid(psirp_id_t*);
psirp_error_t psirpd_sec_pla_add(struct pkt_ctx*);
psirp_error_t psirpd_sec_pla_receive(struct pkt_ctx*);
psirp_error_t psirpd_sec_pla_disable(struct pkt_ctx*);

#endif /* _PSIRPD_SEC_PLA_H */
