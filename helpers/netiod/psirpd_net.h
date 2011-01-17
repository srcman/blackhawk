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


#ifndef _PSIRPD_NET_H
#define _PSIRPD_NET_H

struct pkt_handler;

/** Interface descriptor structure */
struct if_list_item {
    LIST_ENTRY(if_list_item) entries;

    char iface_name[IF_NAMESIZE];     /**< e.g. em0 */
    u_int8_t is_virtual;              /**< is this interface virtual */
    int sock;                         /**< socket */
    struct sockaddr_dl dl;            /**< link-level sockaddr */
    unsigned int bytes_read;          /**  XXXXXX */
    psirp_fid_t lid;                  /**< link ID (bloom filter) */
    struct pkt_handler *handler;     /**> pointer to a handler for this iface */
};

typedef struct if_list_item if_list_item_t;

struct pkt_ctx;

psirp_error_t psirpd_net_init(void);
void psirpd_net_cleanup(void);
psirp_error_t psirpd_net_register(psirp_error_t (*add_iface) 
                                  (if_list_item_t *));
psirp_error_t psirpd_net_init_ifaces(/* char* */);
psirp_error_t psirpd_net_add_iface(char*, u_int8_t);
if_list_item_t* psirpd_net_get_if_list(char*);
psirp_error_t psirpd_net_out(struct pkt_ctx*);
psirp_error_t psirpd_net_regevents(int);
psirp_error_t psirpd_net_unregevents(int);
psirp_error_t psirpd_net_handle_event(struct kevent *);
void psirpd_net_setmask(fd_set*);
psirp_error_t psirpd_net_readmask(fd_set*);

LIST_HEAD(if_list, if_list_item) if_list_head;

#endif /* PSIRPD_NET_H */
