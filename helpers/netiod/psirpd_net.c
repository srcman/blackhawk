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

/* kqueue/kevent */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* read */
#include <sys/uio.h>
#include <unistd.h>

/* libpsirp */
#include <sys/param.h>
#include <libpsirp.h>
#include "../../libpsirp/src/psirp_debug.h"

#include "psirp_common_types.h"
#include "../../libpsirp/src/psirp_old.h"
#include "psirpd_net.h"
#include "psirpd_out_q.h"
#include "psirpd_packet.h"
#include "psirpd_hdrs.h"
#include "psirpd_config.h"

struct net_hook_list_item {
    LIST_ENTRY(net_hook_list_item) entries;
    psirp_error_t (*add_iface) (if_list_item_t *);
};

typedef struct net_hook_list_item net_hook_list_item_t;

LIST_HEAD(net_hook_list, net_hook_list_item) net_hook_list_head;

static psirp_error_t psirpd_net_init_socket(const char *iface_name,
                                            int *sock, struct sockaddr_dl *dl);
static psirp_error_t psirpd_net_check_iface_status(const char *iface_name,
                                                   int sock);
static psirp_error_t psirpd_net_chevents(int, u_int);
static psirp_error_t psirpd_net_in(if_list_item_t *, unsigned int);
static psirp_error_t psirpd_net_out_link(if_list_item_t*, 
                                         u_int8_t*,
                                         u_int32_t);

psirp_error_t
psirpd_net_init(void) { /* xxx change to support n ifnames */ /* XXX: xxx? */

    ENTER();

    LIST_INIT(&if_list_head); 
    LIST_INIT(&net_hook_list_head); 
 
    RETURN PSIRP_OK;
}

void
psirpd_net_cleanup(void)
{
    if_list_item_t *ifli, *ifli2;
    net_hook_list_item_t *cb, *cb2;

    ENTER();

    /* XXX: call unregevents? */

    LIST_FOREACH_SAFE(ifli, &if_list_head, entries, ifli2) {
	if (ifli->sock)
	    close(ifli->sock); /* XXX: ? */
    }

    LIST_FOREACH_SAFE(ifli, &if_list_head, entries, ifli2) {
        LIST_REMOVE(ifli, entries);
        /* Clean up things included in ifli... */

        PSIRP_FREE(ifli);
    }

    LIST_FOREACH_SAFE(cb, &net_hook_list_head, entries, cb2) {
        LIST_REMOVE(cb, entries);
        PSIRP_FREE(cb);
    }

    RETURN;
}

psirp_error_t
psirpd_net_register(psirp_error_t (*add_iface) (if_list_item_t *)) {

    net_hook_list_item_t *cb = NULL;

    ENTER();

    PSIRP_ETL(add_iface == NULL, PSIRP_FAIL_NULL_POINTER, 
              PSIRP_DBG_ERR, "add_iface == NULL");

    PSIRP_MALLOC(cb, sizeof(net_hook_list_item_t));
    memset(cb, 0, sizeof(net_hook_list_item_t));

    cb->add_iface=add_iface;

    LIST_INSERT_HEAD(&net_hook_list_head, cb, entries);

    RETURN PSIRP_OK;
}


psirp_error_t
psirpd_net_init_ifaces(/*char *iface_list*/) {
    
    //char *sep = ",";
    //char *iface;
    config_if_list_item_t *ifitem;
    int is_virtual;

    ENTER();

    /* Add interfaces */
#if 0
    for (iface = strtok(iface_list, sep);
         iface;
         iface = strtok(NULL, sep)) {
#else
    /* Get interface from config file. */
    LIST_FOREACH(ifitem, &config_if_list_head, entries) {
#endif
	/* XXX */
	PSIRP_DEBUG(PSIRP_DBG_GARB, "Adding interface: %s", ifitem->if_name);
	is_virtual = (strcmp(ifitem->if_name, PSIRP_VIRTUAL_IFACE) == 0);
	
	PSIRP_EF(psirpd_net_add_iface(ifitem->if_name, is_virtual));
    }
    
    RETURN PSIRP_OK;
}


psirp_error_t
psirpd_net_add_iface(char *iface_name, u_int8_t is_virtual) {

    if_list_item_t *ifli = NULL;
    net_hook_list_item_t *cb;

    ENTER();

    PSIRP_MALLOC(ifli, sizeof(if_list_item_t));
    memset(ifli, 0, sizeof(if_list_item_t));
    
    memcpy(ifli->iface_name, iface_name, strlen(iface_name));
    
    ifli->is_virtual = is_virtual;

    if (0 == is_virtual) {
        PSIRP_EF(psirpd_net_init_socket(iface_name,
                                        &ifli->sock, &ifli->dl));
        
        psirpd_net_check_iface_status(iface_name, ifli->sock);
    }

    LIST_FOREACH(cb, &net_hook_list_head, entries) {
        PSIRP_DEBUG(PSIRP_DBG_GARB, "Calling registered callbacks");
        PSIRP_EF(cb->add_iface(ifli));
    }

    LIST_INSERT_HEAD(&if_list_head, ifli, entries);

    if (is_virtual) {
        PSIRP_DEBUG(PSIRP_DBG_GARB, 
                    "Initializing virtual interface: %s", iface_name);
    } else {
        PSIRP_DEBUG(PSIRP_DBG_INFO, 
                    "Initializing interface: %s", iface_name);
    }

    RETURN PSIRP_OK;
}

static psirp_error_t
psirpd_net_init_socket(const char *iface_name,
                       int *sock, struct sockaddr_dl *dl) {
    struct ifreq ifr;
    
    ENTER();
    
    *sock = socket(AF_LINK, SOCK_DGRAM, 0);
    PSIRP_ETL(0 > *sock,
	      PSIRP_FAIL,
	      PSIRP_DBG_ERR,
	      "socket(): [%d] %s\n", errno, strerror(errno));
    
    dl->sdl_len = sizeof(*dl) - sizeof(dl->sdl_data);
    dl->sdl_family = AF_LINK;
    
    /* Interface name -> index */
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    PSIRP_ETL(0 > ioctl(*sock, SIOCGIFINDEX, &ifr),
	      PSIRP_FAIL,
	      PSIRP_DBG_ERR,
	      "ioctl(): [%d] %s\n", errno, strerror(errno));
    dl->sdl_index = ifr.ifr_index;

    PSIRP_ETL(0 > bind(*sock, (struct sockaddr *)dl, sizeof(*dl)),
	      PSIRP_FAIL,
	      PSIRP_DBG_ERR,
	      "bind(): [%d] %s\n", errno, strerror(errno));
    
    RETURN(PSIRP_OK);
}

static psirp_error_t
psirpd_net_check_iface_status(const char *iface_name, int sock) {
    struct ifreq ifr;
    
    ENTER();
    
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    PSIRP_ETL(0 > ioctl(sock, SIOCGIFFLAGS, &ifr),
	      PSIRP_FAIL,
	      PSIRP_DBG_ERR,
	      "ioctl(): [%d] %s\n", errno, strerror(errno));
    
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Interface %s flags: 0x%x\n",
                iface_name, ifr.ifr_flags); 
    
    PSIRP_ETL(!((ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_DRV_RUNNING)),
	      PSIRP_FAIL,
	      PSIRP_DBG_WARN,
	      "Interface %s is not UP and RUNNING\n", iface_name);
    
    RETURN(PSIRP_OK);
}


#if 0
psirp_error_t
psirpd_net_remove_iface(char *iface_name) {}
#endif

if_list_item_t*
psirpd_net_get_if_list(char *iface_name) {

    if_list_item_t *ifli = NULL;

    LIST_FOREACH(ifli, &if_list_head, entries) {
        if (0 == strcmp(iface_name, ifli->iface_name)) {
            RETURN ifli;
        }
    }
    RETURN NULL;
}


psirp_error_t
psirpd_net_out(pkt_ctx_t *pkt_ctx) {

    if_list_item_t *iface_out = NULL;
    int i=0;

    ENTER();
    
    pkt_ctx->pkt_len = (pkt_ctx->offset - pkt_ctx->pkt);
    PSIRP_DEBUG(PSIRP_DBG_GARB, "pkt_ctx->pkt_len: %d\n",pkt_ctx->pkt_len); 
    
    /* Send the packet out via each interface in the outgoing list */
    for (i=0; i< pkt_ctx->iface_out_cnt; i++) {
        iface_out= pkt_ctx->iface_out[i];
        
        PSIRP_DEBUG(PSIRP_DBG_GARB, "Sending packet [%s] to: %s\n", 
                    psirpd_packet_get_headers(pkt_ctx), 
		    iface_out->iface_name);
        
        if (iface_out->is_virtual) {
            
            if (NULL == pkt_ctx->iface_in) {
                /* The packet is originated from local host.
                 * To avoid loops we do not want to send it 
                 * to virtual interface in any case. Even the 
                 * bloomfilter earlier matches */
                PSIRP_DEBUG(PSIRP_DBG_GARB, "Skipping iface: %s\n", 
                            iface_out->iface_name);
                continue;
            }
            
            psirpd_packet_in(pkt_ctx->pkt, pkt_ctx->pkt_len, iface_out);
            
        } else {
	    PSIRP_DEBUG(PSIRP_DBG_GARB,
			"Sending out packet of type %u, seqnum=%lu",
			pkt_ctx->rzv_hdr->hdr_type,
			pkt_ctx->rzv_hdr->seqnum);
            psirpd_net_out_link(iface_out, pkt_ctx->pkt, pkt_ctx->pkt_len);
        }
    }

    RETURN PSIRP_OK;



}


static psirp_error_t
psirpd_net_out_link(if_list_item_t *iface_out, 
                    u_int8_t *pkt,
                    u_int32_t pkt_len) {

    ENTER();

    PSIRP_ETL(0 > sendto(iface_out->sock,
			 pkt, pkt_len,
			 MSG_DONTROUTE | MSG_EOR,
			 (struct sockaddr *)&iface_out->dl,
			 sizeof(iface_out->dl)),
	      PSIRP_FAIL,
	      PSIRP_DBG_ERR,
	      "sendto(): [%d] %s\n", errno, strerror(errno));

    PSIRP_DEBUG(PSIRP_DBG_GARB, "Wrote packet to %s\n", 
                iface_out->iface_name);

    RETURN PSIRP_OK;
} 


static psirp_error_t
psirpd_net_chevents(int kq, u_int flags) {

    if_list_item_t *iface_in = NULL;
    static struct kevent cl[1];
    /* XXX: Should we have a changelist with entries for each interface? */

    ENTER();

    LIST_FOREACH(iface_in, &if_list_head, entries) {
        if (!iface_in->is_virtual) {
            memset(cl, 0, sizeof(cl));
            EV_SET(&cl[0],         /* kevent, */
                   iface_in->sock, /* ident,  */
                   EVFILT_READ,    /* filter, */
                   flags,          /* flags,  */
                   0, 0, 0);       /* fflags, data, udata */
            PSIRP_ETL(0 > kevent(kq,      /* kqueue,                */
				 cl, 1,   /* *changelist, nchanges, */
				 NULL, 0, /* *eventlist, nevents,   */
				 NULL),   /* *timeout               */
		      PSIRP_FAIL,
		      PSIRP_DBG_ERR, /* XXX */
		      "kevent(): [%d] %s", errno, strerror(errno));
        }
    }

    RETURN(PSIRP_OK);
}

psirp_error_t
psirpd_net_regevents(int kq) {
    return psirpd_net_chevents(kq, EV_ADD | EV_CLEAR);
}

psirp_error_t
psirpd_net_unregevents(int kq) {
    return psirpd_net_chevents(kq, EV_DELETE);
}

psirp_error_t
psirpd_net_handle_event(struct kevent *el) {
    
    if_list_item_t *iface_in = NULL;
    psirp_error_t err;

    ENTER();
        
    /*
     * XXX: Instead of traversing the list, we could store
     *      ident -> iface mappings somewhere.
     */
    LIST_FOREACH(iface_in, &if_list_head, entries) {
	if (!iface_in->is_virtual &&
	    el->ident == iface_in->sock) {
	    /*
	     * XXXX: Calculate the actual number of bytes
	     *       already read. Events contain a cumulative
	     *       sum, and we might have received multiple
	     *       events from the same interface...
	     *       (Is this needed? And does it work in all cases?)
	     */
	    unsigned int bytes_avail = (unsigned int)el->data;
	    bytes_avail -= iface_in->bytes_read;
            
	    /* XXX: Check flags etc.? */
	    
	    PSIRP_DEBUG(PSIRP_DBG_GARB, "Bytes available: %d\n",
			bytes_avail);
	    err = psirpd_net_in(iface_in, bytes_avail);
	    PSIRP_ETL(PSIRP_OK != err, err, PSIRP_DBG_ERR,
		      "Cannot process the incoming packet\n");
	    RETURN(PSIRP_OK);
	}
    }

    /*
     * XXX: Actually not OK, because the socket was unknown.
     *      (Assuming that we only get net events in this function.)
     */
    RETURN(PSIRP_OK);
}


static psirp_error_t
psirpd_net_in(if_list_item_t *iface_in, unsigned int bytes_avail) {
    
    //int err_pcap;
    //struct pcap_pkthdr *pcap_pkt_hdr = NULL;
    //const unsigned char *data = NULL;
    //struct ether_header *eth_hdr;
    int r;
    unsigned int bytes_left = bytes_avail;
    //psirp_pub_t *pkt_pub = NULL;
#define BUF_LEN PAGE_SIZE /* XXX */ 
    u_int8_t pkt[PAGE_SIZE] = {0}; /* XXX */
    //u_int8_t *pkt = NULL;
    u_int32_t pkt_len = 0;
    psirp_error_t err_psirp;
    //int more;

    ENTER();

    do {
        r = read(iface_in->sock, pkt, BUF_LEN);
        PSIRP_ETL(0 > r, PSIRP_FAIL, PSIRP_DBG_ERR,
		 "read(): [%d] %s\n", errno, strerror(errno));

        pkt_len = r;
        bytes_left -= pkt_len;
        iface_in->bytes_read += pkt_len;
    
        PSIRP_DEBUG(PSIRP_DBG_GARB, "iface_in: %s, pkt_len: %d\n",
                    iface_in->iface_name, pkt_len); 
        PSIRP_DEBUG_HEXDUMP(pkt,pkt_len, 
                            "Pkt excluding Ethernet header:\n"); 
    
        err_psirp = psirpd_packet_in(pkt, pkt_len, iface_in);

    } while (bytes_left > 0);
    
    RETURN err_psirp;
}


