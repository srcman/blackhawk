/*
* Copyright (C) 2009, Oy L M Ericsson Ab, NomadicLab <pubsub@nomadiclab.com>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation.
*
* Alternatively, this software may be distributed under the terms of the BSD
* license.
*
* See LICENSE and COPYING for more details.
*/

#ifndef _PS_HDR_H
#define _PS_HDR_H


//#include <libpsirp.h>
#ifndef LIBPSIRP_H
#define PSIRP_ID_LEN 32
struct psirp_id {
    u_int8_t id[PSIRP_ID_LEN];
};
typedef struct psirp_id psirp_id_t;

#define PSIRP_FID_LEN PSIRP_ID_LEN
typedef psirp_id_t psirp_fid_t;
#endif


/*
 * Next Header Types
 *
 * XXX: If these are eventually supposed to be IPv6 Next Header Types,
 *      we reserve quite many of them... Could, e.g., Options be an
 *      option instead? Or do they need to be related to IPv6 at all?
 */
#define PS_HDR_PID       0xd1 /* Packet (Rendezvous) Identifier */
#define PS_HDR_FID       0xd2 /* Forwarding Identifier */
#define PS_HDR_RFID      0xd3 /* Reverse Forwarding Identifier */
#define PS_HDR_ECCPLA    0xd4 /* ECC / Packet Level Authentication */
#define PS_HDR_VID       0xd5 /* Version (Rendezvous) Identifier */
#define PS_HDR_CRID      0xd6 /* Concept Rendezvous Identifier */
#define PS_HDR_SID       0xd7 /* Scope Identifier */
#define PS_HDR_DATA      0xd8 /* Payload Data */
#define PS_HDR_MTA       0xd9 /* Merkle Tree Authentication */
/* XXX: Do we need any other headers? E.g. for transport? */


#ifndef SWIG
#define PS_HDR_PACKED            __attribute__((__packed__))
#define PS_HDR_PACKED_ALIGNED(x) __attribute__((__packed__, __aligned__(x)))
#else
/*
 * SWIG's parser (and only the parser) doesn't like attributes.
 */
#define PS_HDR_PACKED
#define PS_HDR_PACKED_ALIGNED(x)
#endif


#define PS_HDR_HEAD(prefix)   \
    u_int8_t prefix##_##next; \
    u_int8_t prefix##_##len

#if 1
struct ps_hdr_head {
    PS_HDR_HEAD(phh);
} PS_HDR_PACKED; /* XXX: ? */
typedef struct ps_hdr_head ps_hdr_head_t;
#endif


/* Packet identifier without head -- aligned at a 64 bit boundary */
struct ps_hdr_pid {
   psirp_id_t  php_pid;
} PS_HDR_PACKED_ALIGNED(8);
typedef struct ps_hdr_pid ps_hdr_pid_t;

/* Packet identifier with head after the Ethernet header.
   Aligned at (64 - 16) bit boundary, not enforceable by the compiler */
struct ps_hdr_pid_after_eth {
   PS_HDR_HEAD(php);
   psirp_id_t  php_pid;
} PS_HDR_PACKED;
typedef struct ps_hdr_pid_after_eth ps_hdr_pid_after_eth_t;

/* Packet identifier with head after the UDP header.
   Currently assumed to be aligned at 32 bits boundary, but we need
   to check this later on and figure out how to make this always
   64 bits aligned.  
   At the receiving end, the real amount of padding is defined
   by looking at php_len!
 */
struct ps_hdr_pid_after_udp {
   PS_HDR_HEAD(php);
   psirp_id_t  php_pid;        /* May be only 32 bits aligned? */
   u_int8_t    php_padding[2]; /* Is this amount of padding right */
} PS_HDR_PACKED_ALIGNED(4);
typedef struct ps_hdr_pid_after_udp ps_hdr_pid_after_udp_t;


/* Forwarding Identifier */
struct ps_hdr_fid {
    PS_HDR_HEAD(phf);
    u_int16_t   phf_d;
    u_int8_t    phf_reserved[4]; /* 8? */
    /* Frag. #, QoS, (uni/multi/any)cast, PLA/ECC, TTL, page boundary offset,
     * ...
     */
    psirp_fid_t phf_fid;
} PS_HDR_PACKED_ALIGNED(8);
typedef struct ps_hdr_fid ps_hdr_fid_t;


/* Reverse Forwarding Identifier */
struct ps_hdr_rfid {
    PS_HDR_HEAD(phr);
    u_int8_t    phr_count;
    u_int8_t    phr_reserved[5];
    /* XXX: What's d in this case? */
    psirp_fid_t       phr_rfid[1]; /* XXX: depends on count */
} PS_HDR_PACKED_ALIGNED(8);
typedef struct ps_hdr_rfid ps_hdr_rfid_t;


/* ECC / Packet Level Authentication */
struct ps_hdr_eccpla {
    PS_HDR_HEAD(phe);
    u_int8_t    phe_reserved[6];
    u_int8_t    phe_params[32];
} PS_HDR_PACKED_ALIGNED(8);
typedef struct ps_hdr_eccpla ps_hdr_eccpla_t;

/* Version (Rendezvous) Identifier */
struct ps_hdr_vid {
    PS_HDR_HEAD(phv);
    u_int8_t    phv_reserved[6];
    psirp_id_t  phv_vid;
} PS_HDR_PACKED_ALIGNED(8);
typedef struct ps_hdr_vid ps_hdr_vid_t;


/* Concept Rendezvous Identifier */
struct ps_hdr_crid {
    PS_HDR_HEAD(phc);
    u_int8_t    phc_count;
    u_int8_t    phc_reserved[5];
    psirp_id_t  phc_crid[1]; /* XXX: depends on count */
} PS_HDR_PACKED_ALIGNED(8);
typedef struct ps_hdr_crid ps_hdr_crid_t;

/* Scope Identifier */
struct ps_hdr_sid {
    PS_HDR_HEAD(phs);
    u_int8_t    phs_count;
    u_int8_t    phs_reserved[5];
    psirp_id_t  phs_sid[1]; /* XXX: ? depends on count */
} PS_HDR_PACKED_ALIGNED(8);
typedef struct ps_hdr_sid ps_hdr_sid_t;


/* Payload Data */
struct ps_hdr_data {
    /*
     * XXX: Where do we specify the payload len?
     *      (In IPv6 it's in the first header...)
     */
    PS_HDR_HEAD(phd);           /* XXX: ?? */
    u_int8_t    phd_payload[1]; /* XXX: ?? */
    /* ... */
} PS_HDR_PACKED_ALIGNED(8);
typedef struct ps_hdr_data ps_hdr_data_t;


/* Merkle Tree Authentication */
struct ps_hdr_mta {
    PS_HDR_HEAD(phm);
    u_int8_t    phm_authdata[1]; /* XXX: ?? (depends on len) */
} PS_HDR_PACKED_ALIGNED(8);
typedef struct ps_hdr_mta ps_hdr_mta_t;


#undef PS_HDR_PACKED
#undef PS_HDR_PACKED_ALIGNED
#undef PS_HDR_HEAD

#endif /* _PS_HDR_H */
