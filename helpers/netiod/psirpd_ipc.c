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

/* psirpd_net.h */
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <netinet/in.h> /* XXX */
#include <sys/uio.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

/* libpsirp */
#include <sys/param.h>
#include <libpsirp.h>
#include "../../libpsirp/src/psirp_debug.h"

#include "psirp_common_types.h"
#include "../../libpsirp/src/psirp_old.h"
#include "psirpd_hdrs.h"
#include "psirpd_ipc.h"

#include "psirpd_net.h"
#include "psirpd_out_q.h"
#include "psirpd_packet.h"


static psirp_id_t  ipc_net_rid;
static psirp_id_t  ipc_net_sid;
#if 0
static psirp_pub_t ipc_net_pub;
#endif

static psirp_id_t  ipc_local_sid;
static psirp_id_t  ipc_local_rid,             ipc_local_rid_next;
static psirp_pub_t ipc_local_pub,             ipc_local_pub_next;
static int         ipc_local_pub_prev_vindex, ipc_local_pub_prev_vindex_next;


#define MAX_ACTIVE_PUBS 8
struct active_pub {
    int active;
    psirpd_hdrs_metadata_t md;
    psirp_pub_t pub;
};
static struct active_pub active_pubs[MAX_ACTIVE_PUBS]; /* XXXX */

static psirp_error_t psirpd_ipc_createpub(psirp_id_t *, psirp_id_t *,
                                          psirp_pub_t *,
					  void *, int,
                                          int);
static psirp_error_t psirpd_ipc_chevents(int, u_int, psirp_pub_t, int *);
static psirp_error_t psirpd_ipc_pub_regevents(int, psirp_pub_t, int *);
static psirp_error_t psirpd_ipc_pub_unregevents(int, psirp_pub_t);

static psirp_error_t init_ipc_local_pub(psirp_id_t *, psirp_id_t *,
                                        psirp_pub_t *, int *);
static psirp_error_t handle_ipc_local_pub_version(psirp_pub_t);


psirp_error_t
psirpd_ipc_init(const char *ipc_local_rid_str, const char *ipc_net_rid_str) {
    
    psirp_pub_t ipc_net_pub = NULL;
    
    ENTER();

#if 0    
    PSIRP_ETL(NULL == ipc_local_rid_str, PSIRP_FAIL_NULL_POINTER,
              PSIRP_DBG_ERR, "No IPC RId string for local events");
    PSIRP_ETL(NULL == ipc_net_rid_str, PSIRP_FAIL_NULL_POINTER,
              PSIRP_DBG_ERR, "No IPC RId string for network events");
    /* + Compare? */
#else
    /* XXX: Initialize default IPC RIds */
    psirp_idzero(&ipc_local_rid);
    /* XXX: acdc10:: */
    ipc_local_rid.id[0] = 0xac;
    ipc_local_rid.id[1] = 0xdc;
    ipc_local_rid.id[2] = 0x10;
    psirp_idzero(&ipc_net_rid);
    /* XXX: acdc20:: */
    ipc_net_rid.id[0] = 0xac;
    ipc_net_rid.id[1] = 0xdc;
    ipc_net_rid.id[2] = 0x20;
#endif
    PSIRP_DEBUG(PSIRP_DBG_GARB, "ipc_local_rid = %s" , ipc_local_rid_str);
    PSIRP_DEBUG(PSIRP_DBG_GARB, "ipc_net_rid = %s" , ipc_net_rid_str);
    
    /* Subscribe to the IPC SId/RId for local events. */
    PSIRP_DEBUG(PSIRP_DBG_GARB,
                "Subscribing to IPC publication for local events");
    
    psirp_idzero(&ipc_local_sid);
    /* XXX: acdc:: */
    ipc_local_sid.id[0] = 0xac;
    ipc_local_sid.id[1] = 0xdc;

    if (NULL != ipc_local_rid_str) {
        psirp_idzero(&ipc_local_rid);
        PSIRP_ETL(psirp_atoid(&ipc_local_rid, ipc_local_rid_str),
                  PSIRP_FAIL_INVALIDARG,
                  PSIRP_DBG_ERR, "psirp_atoid()");
    }
    
    ipc_local_pub = NULL;
    ipc_local_pub_prev_vindex = -1;
    
    PSIRP_EF(init_ipc_local_pub(&ipc_local_sid, &ipc_local_rid,
                                &ipc_local_pub,
                                &ipc_local_pub_prev_vindex));
    
    /* Subscribe to the "next" IPC RId as well. */
    memcpy(&ipc_local_rid_next, &ipc_local_rid, sizeof(psirp_id_t));
    psirp_idinc(&ipc_local_rid_next);
    
    ipc_local_pub_next = NULL;
    ipc_local_pub_prev_vindex_next = -1;
    
    PSIRP_EF(init_ipc_local_pub(&ipc_local_sid, &ipc_local_rid_next,
                                &ipc_local_pub_next,
                                &ipc_local_pub_prev_vindex_next));
    
    /* Create a publication for the IPC SId/RId for network events. */
    PSIRP_DEBUG(PSIRP_DBG_GARB,
                "Creating IPC publication for network events");

    memcpy(&ipc_net_sid, &ipc_local_sid, sizeof(psirp_id_t));
    
    if (NULL != ipc_net_rid_str) {
        psirp_idzero(&ipc_net_rid);
        PSIRP_ETL(psirp_atoid(&ipc_net_rid, ipc_net_rid_str),
                  PSIRP_FAIL_INVALIDARG,
                  PSIRP_DBG_ERR, "psirp_atoid()");
    }
    
    ipc_net_pub = NULL;
    PSIRP_EFL(psirpd_ipc_createpub(&ipc_net_sid, &ipc_net_rid,
                                   &ipc_net_pub,
				   NULL, sizeof(psirpd_hdrs_metadata_t),
                                   PSIRP_TRUE),
              PSIRP_DBG_ERR);
    psirp_free(ipc_net_pub);
    
    /* XXXX */
    bzero(&active_pubs, sizeof(active_pubs));
    
    RETURN(PSIRP_OK);
}

static psirp_error_t
init_ipc_local_pub(psirp_id_t *sidp, psirp_id_t *ridp,
                   psirp_pub_t *pubp, int *vindexp) {
    int err = 0;
    
    ENTER();
    
    PSIRP_DEBUG(PSIRP_DBG_GARB,
                "Subscribing to: %s\n", psirp_idstoa(sidp, ridp));
    err = psirp_subscribe_with_flags(sidp, ridp, pubp,
                                     PS_FLAGS_LOCAL_LOCALSUB);
    
    if (0 != err && (ENOENT == errno || /* XXX: */ ESRCH == errno)) {
        psirp_pub_t tmp_pub = NULL;
        
        PSIRP_DEBUG(PSIRP_DBG_GARB,
                    "psirp_subscribe(): [%d] %s",
                    errno, strerror(errno));
        
        /*
         * An IPC publication did not exist, so create and publish a
         * dummy one in order to be able to subscribe.
         */
        PSIRP_DEBUG(PSIRP_DBG_GARB,
                    "No IPC publication exists, creating a dummy one (%s)",
                    psirp_idstoa(sidp, ridp));
        PSIRP_EFL(psirpd_ipc_createpub(sidp, ridp, &tmp_pub,
				       NULL, sizeof(psirpd_hdrs_metadata_t),
                                       PSIRP_TRUE),
                  PSIRP_DBG_ERR);
        err = 0;
        *pubp = tmp_pub;
    }
    
    PSIRP_ETLB(0 != err, PSIRP_FAIL, PSIRP_DBG_ERR,
               {
                   *pubp = NULL;
               },
               "psirp_subscribe(): [%d] %s", errno, strerror(errno));
    
    *vindexp = psirp_pub_current_version_index(*pubp);

    RETURN(PSIRP_OK);
}

psirp_error_t
psirpd_ipc_set_next_ipc_local_pub(void) {
    ENTER();
    
    /* Free old publication. */
    psirp_free(ipc_local_pub);
    
    /* Set next publication and its info to current. */
    ipc_local_pub = ipc_local_pub_next;
    memcpy(&ipc_local_rid, &ipc_local_rid_next, sizeof(psirp_id_t));
    ipc_local_pub_prev_vindex = ipc_local_pub_prev_vindex_next;
    
    /* Subscribe and register next publication. */
    psirp_idinc(&ipc_local_rid_next);
    ipc_local_pub_prev_vindex_next = -1;
    ipc_local_pub_next = NULL;
    PSIRP_EF(init_ipc_local_pub(&ipc_local_sid, &ipc_local_rid_next,
                                &ipc_local_pub_next,
                                &ipc_local_pub_prev_vindex_next));
    
    RETURN(PSIRP_OK);
}

static psirp_error_t
psirpd_ipc_createpub(psirp_id_t *sidp, psirp_id_t *ridp,
		     psirp_pub_t *pubp,
		     void *data, int len,
		     int publish) {
    ENTER();
    
    *pubp = NULL;
    PSIRP_ETLB(0 != psirp_create(len, pubp),
	       PSIRP_FAIL,
	       PSIRP_DBG_ERR,
	       {
		   *pubp = NULL;
	       },
	       "psirp_create(): [%d] %s", errno, strerror(errno));
    PSIRP_ETLB(NULL == psirp_pub_data(*pubp),
               PSIRP_FAIL,
               PSIRP_DBG_ERR,
               {
                   psirp_free(*pubp);
                   *pubp = NULL;
               },
               "No publication data");
    if (NULL != data)
	memcpy(psirp_pub_data(*pubp), data, len);
    else
	bzero(psirp_pub_data(*pubp), psirp_pub_data_len(*pubp));

    if (PSIRP_TRUE == publish) {
        PSIRP_ETLB(0 != psirp_publish(sidp, ridp, *pubp),
                   PSIRP_FAIL,
                   PSIRP_DBG_ERR,
                   {
                       psirp_free(*pubp);
                       *pubp = NULL;
                   },
                   "psirp_publish(): [%d] %s", errno, strerror(errno));
    }
    
    RETURN(PSIRP_OK);
}

void
psirpd_ipc_cleanup()
{
    ENTER();

    //psirpd_ipc_local_unregevents(kq); /* XXX: ? */
    
    if (NULL != ipc_local_pub) {
	psirp_free(ipc_local_pub); /* ? */
        ipc_local_pub = NULL;
    }
    if (NULL != ipc_local_pub_next) {
        psirp_free(ipc_local_pub_next); /* ? */
        ipc_local_pub_next = NULL;
    }
    
    RETURN;
}

static psirp_error_t
psirpd_ipc_chevents(int kq, u_int flags, psirp_pub_t pub, int *fdp) {
    static struct kevent cl[1];
    
    ENTER();

    *fdp = psirp_pub_fd(pub);
    
    EV_SET(&cl[0],                    /* kevent, */
	   *fdp,                      /* ident,  */
	   EVFILT_VNODE,              /* filter, */
           flags,                     /* flags,  */
	   NOTE_PUBLISH | NOTE_UNMAP, /* fflags, */
	   0,                         /* data,   */
           (void *)pub);              /* udata   */
    PSIRP_ETL(0 > kevent(kq,      /* kqueue,                */
                         cl, 1,   /* *changelist, nchanges, */
                         NULL, 0, /* *eventlist, nevents,   */
                         NULL),   /* *timeout               */
              PSIRP_FAIL,
              PSIRP_DBG_ERR,
	      "kevent(): [%d] %s", errno, strerror(errno));
    
    RETURN(PSIRP_OK);
}

static inline psirp_error_t
psirpd_ipc_pub_regevents(int kq, psirp_pub_t pub, int *fdp) {
    return psirpd_ipc_chevents(kq, EV_ADD | EV_CLEAR, pub, fdp);
}

static inline psirp_error_t
psirpd_ipc_pub_unregevents(int kq, psirp_pub_t pub) {
    int dummy_fd;
    return psirpd_ipc_chevents(kq, EV_DELETE, pub, &dummy_fd);
}

psirp_error_t
psirpd_ipc_local_regevents(int kq, int *fdp) {
    return psirpd_ipc_pub_regevents(kq, ipc_local_pub, fdp);
}

psirp_error_t
psirpd_ipc_local_next_regevents(int kq, int *fdp) {
    return psirpd_ipc_pub_regevents(kq, ipc_local_pub_next, fdp);
}

psirp_error_t
psirpd_ipc_local_unregevents(int kq) {
    return psirpd_ipc_pub_unregevents(kq, ipc_local_pub);
}

psirp_error_t
psirpd_ipc_local_handle_event(struct kevent *el) {
    int i1, i2, n;
    
    ENTER();

    /*
     * The new(est) version has been automatically mapped for us, and
     * the previous version has been freed. But there can be
     * intermediate versions as well that we need to process first.
     */
    i1 = ipc_local_pub_prev_vindex;
    i2 = psirp_pub_current_version_index(ipc_local_pub);
    n = i2 - i1;
    {
        psirp_pub_t versions[n];
        int j, m;
        
        bzero(versions, n*sizeof(psirp_pub_t));
        PSIRP_DEBUG(PSIRP_DBG_GARB, "Subscribing to %d versions", n);
        m = psirp_subscribe_versions(ipc_local_pub,
                                     versions,
                                     i1+1,
                                     n);
        ipc_local_pub_prev_vindex = i2;
        if (m != n) {
            PSIRP_DEBUG(PSIRP_DBG_WARN,
                        "Expected a different number of versions "
                        "(%d instead of %d)", n, m);                        
        }
        
        for (j = 0; j < m; j++) {
            handle_ipc_local_pub_version(versions[j]);
            /* XXX: Maybe we should check the return value. */
            psirp_free(versions[j]);
            versions[j] = NULL;
        }
    }

    RETURN(PSIRP_OK);
}

static psirp_error_t
handle_ipc_local_pub_version(psirp_pub_t version) {
    psirpd_hdrs_metadata_t *ipc_data = NULL;

    ENTER();

    PSIRP_ET(psirp_pub_data_len(version) < sizeof(psirpd_hdrs_metadata_t),
             PSIRP_FAIL,
             "Not an IPC publication");
    
    ipc_data =
	(psirpd_hdrs_metadata_t *)psirp_pub_data(version);
        
    switch (ipc_data->rzvhdr_type) {
    case PSIRP_HDR_RZV_PUBLISH_METADATA:
	PSIRP_DEBUG(PSIRP_DBG_INFO, "Event: publish metadata");
	PSIRP_EF(psirpd_packet_out_metadata(&ipc_data->sid,
					    &ipc_data->rid,
                                            &ipc_data->vrid,
					    &ipc_data->fid,
					    ipc_data->len));
	PSIRP_DEBUG(PSIRP_DBG_INFO, "Sent publication metadata");
	break;
    case PSIRP_HDR_RZV_PUBLISH_DATACHUNK:
	PSIRP_DEBUG(PSIRP_DBG_INFO, "Event: publish datachunk");
	psirpd_packet_out_queuechunks(&ipc_data->sid,
				      &ipc_data->rid,
				      &ipc_data->vrid,
				      &ipc_data->fid);
        break;
    case PSIRP_HDR_RZV_SUBSCRIBE_METADATA:
	PSIRP_DEBUG(PSIRP_DBG_INFO, "Event: subscribe metadata");
	PSIRP_EF(psirpd_packet_out_submetadata(&ipc_data->sid,
					       &ipc_data->rid,
					       &ipc_data->vrid,
					       &ipc_data->fid,
                                               ipc_data->flags));
	PSIRP_DEBUG(PSIRP_DBG_INFO, "Sent subscription to metadata");
        break;
    case PSIRP_HDR_RZV_SUBSCRIBE_DATACHUNK:
	PSIRP_DEBUG(PSIRP_DBG_INFO, "Event: subscribe datachunk");
	{
	    psirpd_ipc_metadata_ext_t *md_ext;
	    psirp_fid_t *md_fidp;
            int i;
	    
	    PSIRP_ETL(psirp_pub_data_len(version)
		      < sizeof(psirpd_ipc_hdrs_metadata_ext_t),
		      PSIRP_FAIL, PSIRP_DBG_ERR,
		      "Expected extended metadata");
	    md_ext =
		&((psirpd_ipc_hdrs_metadata_ext_t *)
		  psirp_pub_data(version))->md_ext;
	    md_fidp = &md_ext->fid;
	    
	    /* XXXX */
	    if (!md_ext->relay) {
                /* Find a free active publication slot */
                for (i = 0; i < MAX_ACTIVE_PUBS; i++) {
                    if (!active_pubs[i].active) {
                        struct active_pub *ap = &active_pubs[i];
                        
                        ap->active = 1;
                        
                        PSIRP_DEBUG(PSIRP_DBG_INFO,
                                    "Set active publication %d metadata, "
                                    "SId/RId/V-RId: %s, len: %d",
                                    i,
                                    psirp_debug_idstoa(&ipc_data->sid,
                                                       &ipc_data->rid,
                                                       &ipc_data->vrid,
                                                       NULL),
                                    ipc_data->len);
                        
                        memcpy(&ap->md.sid, &ipc_data->sid, sizeof(psirp_id_t));
                        memcpy(&ap->md.rid, &ipc_data->rid, sizeof(psirp_id_t));
                        memcpy(&ap->md.vrid, &ipc_data->vrid,
                               sizeof(psirp_id_t));
                        ap->md.len = ipc_data->len;
                        ap->md.max_seqnum = 0;
                        
                        PSIRP_DEBUG(PSIRP_DBG_GARB,
                                    "Create active publication");
                        PSIRP_EFL(psirpd_ipc_createpub(NULL, NULL,
                                                       &ap->pub,
                                                       NULL, ap->md.len,
                                                       PSIRP_FALSE),
                                  PSIRP_DBG_ERR);
                        
                        break;
                    }
                    PSIRP_ETL(i >= MAX_ACTIVE_PUBS, PSIRP_FAIL, PSIRP_DBG_ERR,
                              "No active publication slots free");
                }
            }
	    
	    {
		char fid_str[PSIRP_ID_LEN*2+1];
		memcpy(fid_str, psirp_idtoa(&ipc_data->fid),
		       sizeof(psirp_fid_t));
                
		PSIRP_DEBUG(PSIRP_DBG_INFO,
			    "Data subscription metadata:\n"
			    "         SId/RId/V-RId/FId: %s\n"
			    "         Out-FId: %s",
			    psirp_debug_idstoa(&ipc_data->sid,
                                               &ipc_data->rid,
                                               &ipc_data->vrid,
                                               md_fidp),
                            &fid_str);
	    }
	    
	    psirpd_packet_out_subdata(&ipc_data->sid,
				      &ipc_data->rid,
				      &ipc_data->vrid,
				      md_fidp,
				      &ipc_data->fid,
				      md_ext->relay);
	}
        break;
    default:
        PSIRP_ET(PSIRP_TRUE, PSIRP_FAIL, "Unknown IPC publication type");/*XXX*/
        break;
    }
    
    RETURN(PSIRP_OK);
}

psirp_error_t
psirpd_ipc_net_handle_metadata(psirpd_hdrs_metadata_t *md_hdr) {
    /*
     * We have received publication metadata or a subscription from
     * the network. We pass it on to the local rendezvous daemon by
     * creating and publishing an IPC publication.
     */
    
    psirp_pub_t ipc_net_pub = NULL;
    
    ENTER();

#if 0    
    PSIRP_DEBUG(PSIRP_DBG_GARB,
		"hdr_type=0x%02x, nxt_hdr=0x%02x, rzvhdr_type=0x%02x, "
		"sid/rid/vrid/fid=%s, ...",
		md_hdr->hdr_type, md_hdr->nxt_hdr, md_hdr->rzvhdr_type,
		psirp_debug_idstoa(&md_hdr->sid, &md_hdr->rid,
                                   &md_hdr->vrid, &md_hdr->fid));
#endif
    PSIRP_DEBUG(PSIRP_DBG_INFO,
                "Publishing received metadata on the blackboard:\n%s",
                psirpd_hdrs_metadata_to_str(md_hdr));
    
    PSIRP_DEBUG(PSIRP_DBG_GARB, "Publish metadata as IPC publication");
    PSIRP_EFL(psirpd_ipc_createpub(&ipc_net_sid, &ipc_net_rid,
                                   &ipc_net_pub,
				   md_hdr, sizeof(*md_hdr),
                                   PSIRP_TRUE),
              PSIRP_DBG_ERR);
    if (psirp_pub_version_count(ipc_net_pub) >= 100) { /* XXX */
        /* Ideally, we would do this before publishing, not after. */
        psirp_idinc(&ipc_net_rid);
        PSIRP_DEBUG(PSIRP_DBG_INFO,
                    "Switching to next IPC net RId: %s",
                    psirp_idtoa(&ipc_net_rid));
    }
    psirp_free(ipc_net_pub);
    
    RETURN(PSIRP_OK);
}

psirp_error_t
psirpd_ipc_net_handle_data(psirpd_hdrs_rzvhdr_t *rzvhdr,
			   void *payload, u_int64_t len) {
    
    ENTER();

    PSIRP_DEBUG(PSIRP_DBG_GARB, "seqnum=%lu", rzvhdr->seqnum);
    
    /* XXXX */
    if (rzvhdr->hdr_type == PSIRP_HDR_RZV_PUBLISH_DATACHUNK) {
        int i;
        
        for (i = 0; i < MAX_ACTIVE_PUBS; i++) {
            /* Find correct active publication */
            if (active_pubs[i].active) {
                struct active_pub *ap = &active_pubs[i];
                
                if (0 == psirp_idcmp(&rzvhdr->sid, &ap->md.sid)
                    && 0 == psirp_idcmp(&rzvhdr->rid, &ap->md.rid)
                    && 0 == psirp_idcmp(&rzvhdr->vrid, &ap->md.vrid)) {
                    /* Matches to existing active pub */
                    
                    PSIRP_DEBUG(PSIRP_DBG_GARB,
                                "Copying data chunk to publication, "
                                "seqnum=%d", rzvhdr->seqnum);
                    memcpy((psirp_pub_data(ap->pub)
                            + PSIRP_CHUNK_SIZE*rzvhdr->seqnum),
                           payload,
                           len);
                    
                    if (ap->md.max_seqnum > 0
                        && rzvhdr->seqnum != ap->md.max_seqnum-1) {
                        
                        PSIRP_DEBUG(PSIRP_DBG_WARN,
                                    "Seqnum: %d != %d-1, packet lost?",
                                    rzvhdr->seqnum, ap->md.max_seqnum);
                    }
                    ap->md.max_seqnum = rzvhdr->seqnum;
                    
                    if (rzvhdr->seqnum == 0) {
                        PSIRP_DEBUG(PSIRP_DBG_INFO,
                                    "Last publication data chunk received");
                        
                        /* Publish active publication */
                        PSIRP_ETLB(0 != psirp_publish(&ap->md.sid,
                                                      &ap->md.rid,
                                                      ap->pub),
                                   PSIRP_FAIL,
                                   PSIRP_DBG_ERR,
                                   {
                                       /* Free slot */
                                       psirp_free(ap->pub);
                                       bzero(ap, sizeof(struct active_pub));
                                   },
                                   "psirp_publish(): [%d] %s",
                                   errno, strerror(errno));	    
                        
                        if (0 != psirp_idcmp(psirp_pub_current_version(ap->pub),
                                             &ap->md.vrid)) {
                            PSIRP_DEBUG(PSIRP_DBG_WARN,
                                        "Version-RIds of publication and"
                                        "subscription do not match.");
                        }
                        
                        /* Free slot */
                        psirp_free(ap->pub);
                        bzero(ap, sizeof(struct active_pub));
                    }
                    
                    break;
                }
            }
        }
	PSIRP_ETL(i == MAX_ACTIVE_PUBS, PSIRP_FAIL, PSIRP_DBG_ERR,
		  "Received data chunk for non-active publication, "
		  "SId/RId/V-RID: %s", psirp_debug_idstoa(&rzvhdr->sid,
                                                          &rzvhdr->rid,
                                                          &rzvhdr->vrid,
                                                          NULL));
    }
    
    RETURN(PSIRP_OK);
}

char *psirpd_ipc_hdrs_metadata_ext_to_str(struct psirpd_ipc_hdrs_metadata_ext
                                          *md_hdr_ext) {    
    char *md_str;
    int len;
    
    char ext_fid_str[2 * PSIRP_ID_LEN + 1] = { 0 };
        
    struct psirpd_hdrs_metadata    *md_hdr = &md_hdr_ext->md_hdr;
    struct psirpd_ipc_metadata_ext *md_ext = &md_hdr_ext->md_ext;

    md_str = psirpd_hdrs_metadata_to_str(md_hdr);
    len = strlen(md_str);
    
    memcpy(ext_fid_str, psirp_idtoa(&md_ext->fid),
           sizeof(ext_fid_str));
    
    snprintf(md_str + len*sizeof(char), /*XXX*/1024 - len,
             "         -----------\n" \
             "         FId:     %s\n" \
             "         relay:   %d",
             ext_fid_str,
             md_ext->relay);
    
    return md_str;
}
