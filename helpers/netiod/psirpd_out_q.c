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

/* psirpd_net.h */
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>

#include <sys/param.h>
#include <libpsirp.h>
#include "../../libpsirp/src/psirp_debug.h"

#include "psirp_common_types.h"
#include "../../libpsirp/src/psirp_old.h"
#include "psirpd_hdrs.h"
#include "psirpd_net.h"
#include "psirpd_out_q.h"
#include "psirpd_packet.h"

STAILQ_HEAD(out_q_list, out_q_list_item) out_q_list_head;

static out_q_list_item_t *item_out = NULL;

psirp_error_t
psirpd_out_q_init(void) {

    /* XXX should this be called from somewhere?? */

    STAILQ_INIT(&out_q_list_head); 
    return PSIRP_OK;
}

void
psirpd_out_q_cleanup(void) {

    /* XXX should this be called from somewhere?? */

    out_q_list_item_t *p1;

    while (!STAILQ_EMPTY(&out_q_list_head)) {
        p1 = STAILQ_FIRST(&out_q_list_head);
        STAILQ_REMOVE_HEAD(&out_q_list_head, entries);
        PSIRP_FREE(p1);
    }
}

/** 
 * Function that is called for allocating an out queue item.
 * @return out queue list item
 */
out_q_list_item_t*
psirpd_out_q_create_item(psirp_id_t *sidp,
                         psirp_id_t *ridp,
                         psirp_id_t *vridp,
			 psirp_fid_t *fidp,
			 psirp_pub_t *pubp,
			 int *countp,
			 u_int64_t seqnum) {
    //psirp_error_t err;
    out_q_list_item_t *item;

    ENTER();
    
    PSIRP_MALLOC(item, sizeof(out_q_list_item_t));
    memset(item, 0, sizeof(out_q_list_item_t));

#if 0
    item->fid = *fidp;
    item->rid = *ridp;
    item->sid = *sidp;
    item->vrid = *vridp;
#else
    memcpy(&item->fid, fidp, sizeof(psirp_fid_t));
    memcpy(&item->sid, sidp, sizeof(psirp_id_t));
    memcpy(&item->rid, ridp, sizeof(psirp_id_t));
    memcpy(&item->vrid, vridp, sizeof(psirp_id_t));
#endif
    
    item->pubp   = pubp;
    item->countp = countp;
    item->seqnum = seqnum;
    
    RETURN item;
}

/** 
 * Function that is called for freeing memory that is allocated for
 * the out queue item.
 * @param item pointer to the out queue item
 * @return void
 */
void
psirpd_out_q_free_item(out_q_list_item_t *item) {

    ENTER();
    
    if (*(item->countp) < 0) {
	
	PSIRP_DEBUG(PSIRP_DBG_INFO,
		    "All chunks sent for SId/RId/vRId/FId: %s",
                    psirp_debug_idstoa(&item->sid,  &item->rid,
                                       &item->vrid, &item->fid));
	
	psirp_free(*item->pubp);
	*item->pubp = NULL;
	
	PSIRP_FREE(item->pubp);
	item->pubp = NULL;
	
	PSIRP_FREE(item->countp);
	item->countp = NULL;
    }
    
    PSIRP_FREE(item);
    
    RETURN;
}

/** 
 * Function that is called for adding the out queue item to the 
 * out queue list.
 * @param item1 pointer to the out queue item
 * @return void
 */
void
psirpd_out_q_add_item(out_q_list_item_t *item1) {

    ENTER();

    if (STAILQ_EMPTY(&out_q_list_head)) {
        item_out = item1;
    }
    else {
        out_q_list_item_t *item2;
        /*
         * Check if an identical item (i.e., the same data chunk) has
         * already been queued (probably with a different FId). It is
         * found, add the FId of this item to the FId of the existing one
         * and discard the new item. This implements a simple form of
         * multicast.
         */
        STAILQ_FOREACH(item2, &out_q_list_head, entries) {
            int i;
            
            if (item1->seqnum == 0) {
                /*
                 * XXXX: If the sequence number is 0 (the termination
                 *       indicator) we add the item normally, i.e., at the
                 *       end of the queue. Otherwise a publication might
                 *       get published too soon at a "late" subscriber who
                 *       should still wait for queued chunks from the
                 *       beginning of the publication.
                 */
                break;
            }
            
            if((item2->seqnum == item1->seqnum) &&
               !memcmp(&item2->vrid, &item1->vrid, sizeof(psirp_id_t)) &&
               !memcmp(&item2->rid,  &item1->rid,  sizeof(psirp_id_t)) &&
               !memcmp(&item2->sid,  &item1->sid,  sizeof(psirp_id_t))) {
                /* Identical item found. */
                PSIRP_DEBUG(PSIRP_DBG_GARB,
                            "Same item found: %s, %lu",
                            psirp_debug_idstoa(&item2->sid,  &item2->rid,
                                               &item2->vrid, &item2->fid),
                            item2->seqnum);
                
                /* OR FIds to create the multicast tree. */
                for (i = 0; i < PSIRP_FID_LEN; i++) {
                    item2->fid.id[i] |= item1->fid.id[i];
                }
                
                PSIRP_DEBUG(PSIRP_DBG_GARB,
                            "Updated FId of queued item: %s (%ld)",
                            psirp_idtoa(&item2->fid),
                            item2->seqnum);
                
                /* Decrement counter and discard new item. */
                *(item1->countp) -= 1;
                psirpd_out_q_free_item(item1);
                
                RETURN;
            }
        }
    }

    STAILQ_INSERT_TAIL(&out_q_list_head, item1, entries);

    RETURN;
}
              
/** 
 * Function is called during every kevent() timeout. The function loops
 * the out queue list and sends out data packets..  
 * @return On sucess: PSIRP_OK <br>On failure: PSIRP_FAIL_ error code
 */
psirp_error_t
psirpd_out_q_send(void) {
    
    u_int8_t *addr;
    out_q_list_item_t *item_next = NULL;
    psirp_error_t retval = PSIRP_OK;
    int i;

    ENTER();

    item_out = STAILQ_FIRST(&out_q_list_head);

    for (i = 0; i < PSIRP_OUTQ_BATCH_SIZE; i++) {
	if (NULL == item_out) {
	  retval = PSIRP_OK;
	  break;
	}
	
	addr = (u_int8_t *)(psirp_pub_data(*(item_out->pubp))
			    + item_out->seqnum*PSIRP_CHUNK_SIZE);
	
	PSIRP_DEBUG(PSIRP_DBG_GARB,
		    "Send chunk out (count=%l, seqnum=%lu, addr=%p)",
		    *(item_out->countp), item_out->seqnum, addr);
	retval = psirpd_packet_out_data(addr, 
					PSIRP_CHUNK_SIZE, 
					item_out);
	*(item_out->countp) -= 1;
	
	item_next = STAILQ_NEXT(item_out, entries);
	if (NULL == item_next) {
	    PSIRP_DEBUG(PSIRP_DBG_GARB, "We are at the end of the list");
	}
	
	STAILQ_REMOVE_HEAD(&out_q_list_head, entries);
	psirpd_out_q_free_item(item_out);
	
	item_out = item_next;
    }
    
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Sent out %d packets at once", i);

    RETURN retval;
}

struct timespec *
psirpd_out_q_next_timeout(struct timespec *time) {
    if (NULL != item_out) {
        /* Things in outqueue. */
        time->tv_sec  = PSIRP_OUTQ_TIMEOUT_SEC;
        time->tv_nsec = PSIRP_OUTQ_TIMEOUT_NSEC;
        return time;
    } else {
        /* Nothing in outqueue. */
        return NULL;
    }
}
