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

/*
 * XXX: Check and document the locking design.
 */

#include <sys/param.h>
#include <sys/domain.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/lock.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_var.h>
#include <net/if_arp.h>

//#include "ps.h"

#include "ps_socket.h"
#include "ps_debug.h"

/* Buffer space */
static u_long ps_sendspace = 48 * 1500;	/* really max datagram size (?) */
static u_long ps_recvspace = 96 * 1500; /* affects packet loss */

#define sotopspcb(so) ((struct pspcb *)((so)->so_pcb))

LIST_HEAD(, pspcb) _pspcbhead, *pspcbhead = &_pspcbhead;
static struct mtx _pspcb_lock, *pspcb_lock = &_pspcb_lock;
MTX_SYSINIT(pspcb_lock, &_pspcb_lock, "pubsub pcb head lock", 0);

struct pspcb {
    LIST_ENTRY(pspcb) psp_list;	/* list for app PCBs  */
    struct socket *psp_socket;
    struct rwlock  psp_lock;
    struct ifnet *psp_ifp;
};

static void ps_ether_input(struct ifnet *ifp, struct mbuf **mp);
static void ps_ether_input_orphan(struct ifnet *ifp, struct mbuf *m);
static int  ps_ether_output(struct ifnet *ifp, struct mbuf **mp);
static void ps_ether_detach(struct ifnet *ifp);
static void ps_ether_link_state(struct ifnet *ifp, int state);

extern void (*ng_ether_input_p)(struct ifnet *ifp, struct mbuf **mp);
extern void (*ng_ether_input_orphan_p)(struct ifnet *ifp, struct mbuf *m);
extern int  (*ng_ether_output_p)(struct ifnet *ifp, struct mbuf **mp);
extern void (*ng_ether_detach_p)(struct ifnet *ifp);
extern void (*ng_ether_link_state_p)(struct ifnet *ifp, int state);

/*
 * Caveat:  Called from interrupt context
 */
static void
ps_ether_input(struct ifnet *ifp, struct mbuf **mp) {
    struct pspcb *psp = NULL, *psp_next;
    struct ether_header *eh;
    struct sockaddr esa;
    struct socket *so = NULL;
    u_short etype;

    eh = mtod(*mp, struct ether_header *);
    etype = ntohs(eh->ether_type);

    if (PS_ETHER_TYPE != etype)
	return;

    /*
     * We currently place the mbuf to a bound socket's rcv.
     *
     * However,this is not the long term plan.  Instead, in the 
     * longer term we should fill in a page, place the page at
     * the local cache, and then wake up the network receiver.
     * through the bound socket.
     */

    PS_PRINTF(PS_DEBUG_SOCKET, "m = %p\n", *mp);
    LIST_FOREACH_SAFE(psp, pspcbhead, psp_list, psp_next) {
#if __FreeBSD_version >= 701000
	if (!rw_try_rlock(&psp->psp_lock)) {
            PS_PRINTF(PS_DEBUG_SOCKET | PS_DEBUG_WARNING,
                      "psp is w-locked, discard data\n");
	    /* Simply discard data if the psp happens to be w-locked */
	    continue;
	}
#endif
	if (ifp == psp->psp_ifp) {
	    so = psp->psp_socket;
#if __FreeBSD_version >= 701000
	    rw_runlock(&psp->psp_lock);
#endif
	    break;
	}
#if __FreeBSD_version >= 701000
	rw_runlock(&psp->psp_lock);
#endif
    }

    if (so) {
	/*
	 * XXX: We don't understand why simple sbappend
	 *      doesn't work.  But spappendaddr does.  So be it.
	 */
	esa.sa_family = AF_LINK;
	esa.sa_len = 0;
	m_adj(*mp, sizeof(*eh)); /* Remove ethernet header */
	if (!sbappendaddr(&so->so_rcv, &esa, *mp, NULL)) {
            PS_PRINTF(PS_DEBUG_SOCKET | PS_DEBUG_WARNING,
                      "sbappendaddr() failed. "
                      "Probably not enough buffer space. "
                      "Packet lost.\n");
        }
	sorwakeup(so);
    	*mp = NULL;
	return;
    }


#ifdef NOTYET
    /* We could free *mp here, but we don't.  It gets discarded anyway */
    m_freem(*mp);
    *mp = NULL;
#endif
    return;
}

static void 
ps_ether_input_orphan(struct ifnet *ifp, struct mbuf *m) {
    return;
}

static int  
ps_ether_output(struct ifnet *ifp, struct mbuf **mp) {
    return 0;
}

static int
ps_attach(struct socket *so, int proto, struct thread *td) {
    struct pspcb *psp = sotopspcb(so);
    int error;

    PS_PRINTF(PS_DEBUG_SOCKET, "so = %p, proto=%d\n", so, proto);

    if (NULL != psp)
	return (EISCONN);
    
    error = soreserve(so, ps_sendspace, ps_recvspace);
    if (error)
	return (error);

    psp = malloc(sizeof(struct pspcb), M_PCB, M_WAITOK | M_ZERO);
    
    rw_init(&psp->psp_lock, "psp_lock");
    psp->psp_ifp = NULL;

    so->so_pcb = (caddr_t)psp;
    psp->psp_socket = so;

    mtx_lock(pspcb_lock);
    LIST_INSERT_HEAD(pspcbhead, psp, psp_list);
    mtx_unlock(pspcb_lock);

    return (0);
}

static void
ps_detach(struct socket *so) {
    struct pspcb *psp = sotopspcb(so);

    PS_PRINTF(PS_DEBUG_SOCKET, "so = %p\n", so);

    KASSERT(psp != NULL, ("ps_detach: psp == NULL"));
    mtx_lock(pspcb_lock);
    rw_wlock(&psp->psp_lock);
    LIST_REMOVE(psp, psp_list);
    mtx_unlock(pspcb_lock);
    if (psp->psp_ifp)
	IFP2AC(psp->psp_ifp)->ac_netgraph = NULL;
    psp->psp_socket->so_pcb = NULL;
    free(psp, M_PCB);
}

static void 
ps_ether_detach(struct ifnet *ifp) {
    struct pspcb *psp, *psp_next;

    LIST_FOREACH_SAFE(psp, pspcbhead, psp_list, psp_next) {
	rw_wlock(&psp->psp_lock);
	if (ifp == psp->psp_ifp) {
	    IFP2AC(ifp)->ac_netgraph = NULL;
	    psp->psp_ifp = NULL;
	    rw_wunlock(&psp->psp_lock);
	    return;
	}
	rw_wunlock(&psp->psp_lock);
    }
}

static void
ps_ether_link_state(struct ifnet *ifp, int state) {
    return;
}

static int
ps_bind(struct socket *so, struct sockaddr *addr, struct thread *td) {
    struct pspcb *const psp = sotopspcb(so);
    struct ifaddr *ifa;
    struct ifnet *ifp;
    int error = 0;

    PS_PRINTF(PS_DEBUG_SOCKET, "so = %p, addr=%p, sa_family=%d\n", 
	      so, addr, addr->sa_family);

    if (psp == NULL) {
	error = EINVAL;
	goto done;
    }

    /*
     * Find the right interface
     */
#if __FreeBSD_version < 801000 || __FreeBSD_version >= 900000
    ifa = ifa_ifwithnet(addr);
#else
    ifa = ifa_ifwithnet(addr, 0);
#endif
    if (NULL == ifa) {
	error = EADDRNOTAVAIL;
	goto done;
    }
    ifp = ifa->ifa_ifp;
    KASSERT(NULL != ifp, ("ps_send: ifp not found for ifa"));

    rw_wlock(&psp->psp_lock);
    psp->psp_ifp = ifp;
    rw_wunlock(&psp->psp_lock);

    PS_PRINTF(PS_DEBUG_SOCKET,
	      "ifp->if_dname=%s%d\n", ifp->if_dname, ifp->if_dunit);


    /*
     * Hook a netgraph input filter to the interface.
     *
     * XXX: This is a gross hack!
     * See around at if_ethersubr.c:638 in ether_input()
     */
    IFP2AC(ifp)->ac_netgraph = (void *)1;

 done:
    return error;
}

static int
ps_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
	 struct mbuf *control, struct thread *td) {
    static const u_char ether_broadcast[ETHER_ADDR_LEN] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    struct pspcb *const psp = sotopspcb(so);
    struct sockaddr esa;
    struct ether_header eh;
    struct ifaddr *ifa;
    int error = 0;

    PS_PRINTF(PS_DEBUG_SOCKET, "sa_family=%d\n", addr->sa_family);

    if ((psp == NULL) || (control != NULL)) {
	error = EINVAL;
	goto release;
    }

    /*
     * Find the right interface
     */
#if __FreeBSD_version < 801000 || __FreeBSD_version >= 900000
    ifa = ifa_ifwithnet(addr);
#else
    ifa = ifa_ifwithnet(addr, 0);
#endif
    if (NULL == ifa) {
	error = EADDRNOTAVAIL;
	goto release;
    }
    KASSERT(NULL != ifa->ifa_ifp, ("ps_send: ifp not found for ifa"));

    PS_PRINTF(PS_DEBUG_SOCKET, "ifp->if_dname=%s%d\n", 
	      ifa->ifa_ifp->if_dname, ifa->ifa_ifp->if_dunit);

    /*
     * Build pubsub header ?????
     *
     * XXX
     */

    /*
     * Build the Ethernet header
     */
    memset(&eh, 0, sizeof(eh));
    eh.ether_type = htons(PS_ETHER_TYPE);
    memcpy(eh.ether_dhost, ether_broadcast, sizeof(eh.ether_dhost));
#if 0
    /* Hide source address. */
    memcpy(eh.ether_shost, ether_broadcast, sizeof(eh.ether_shost));
#else
    /* Use real source address. Some switches etc. need this. */
    memcpy(eh.ether_shost, IF_LLADDR(ifa->ifa_ifp), sizeof(eh.ether_shost));
#endif
    esa.sa_family = pseudo_AF_HDRCMPLT;
    (void)memcpy(esa.sa_data, &eh, sizeof(eh));

    /*
     * Send out
     */
    error = ether_output(ifa->ifa_ifp, m, &esa, NULL);
    PS_PRINTF(PS_DEBUG_SOCKET, "ether_output -> %d\n", error);
    return error;

 release:
    if (control != NULL)
	m_freem(control);
    if (m != NULL)
	m_freem(m);
    return (error);
}

static int
ps_getsockaddr(struct socket *so, struct sockaddr **addr) {
    return (0);
}

static int 
dummy_disconnect(struct socket *so) {
    return (0);
}

static struct pr_usrreqs ps_usrreqs = {
    .pru_abort =           NULL,
    .pru_attach =          ps_attach,
    .pru_bind =            ps_bind,
    .pru_connect =         NULL,
    .pru_detach =          ps_detach,
    .pru_disconnect =      dummy_disconnect,
    .pru_peeraddr =        NULL,
    .pru_send =            ps_send,
    .pru_shutdown =        NULL,
    .pru_sockaddr =        ps_getsockaddr,
#if __FreeBSD_version >= 800000
    .pru_sosend =          sosend_generic,
    .pru_soreceive =       soreceive_generic,
    .pru_sopoll =          sopoll_generic,
#endif
    .pru_close =           NULL,
};


extern struct domain psdomain;

static struct protosw pssw[] = { 
{
    .pr_type =             SOCK_DGRAM,
    .pr_domain =           &psdomain,
    .pr_protocol =         PROTO_PUBSUB,	/* XXX */
    .pr_flags =            PR_ATOMIC | PR_ADDR, /* XXX???? */
    .pr_usrreqs =          &ps_usrreqs,
},
};

struct domain psdomain = {
    .dom_family =	   AF_LINK,
    .dom_name =            "pubsub",
    .dom_protosw =         pssw,
    .dom_protoswNPROTOSW = &pssw[sizeof(pssw) / sizeof(pssw[0])],
};

int ps_socket_init(void) {
    LIST_INIT(pspcbhead);
#if __FreeBSD_version < 800000
    net_add_domain(&psdomain);
#else
    domain_add(&psdomain);
#endif

    /*
     * Fake netgraph input filter.
     */
    ng_ether_input_p = ps_ether_input;
    ng_ether_input_orphan_p = ps_ether_input_orphan;
    ng_ether_output_p = ps_ether_output;
    ng_ether_detach_p = ps_ether_detach;
    ng_ether_link_state_p = ps_ether_link_state;

    return 0;
}

extern struct mtx dom_mtx;

int ps_socket_cleanup(void) {

    if (!LIST_EMPTY(pspcbhead)) {
	return EBUSY;
    }

    ng_ether_input_p = NULL;
    ng_ether_input_orphan_p = NULL;
    ng_ether_output_p = NULL;
    ng_ether_detach_p = NULL;
    ng_ether_link_state_p = NULL;

#ifdef NOTYET
    return net_rm_domain(&psdomain);
#else
    /*
     * Ugly hack to remove the domain....  ARGH!
     *
     * We currently only support this as the last added domain.
     * Works well enough for us, since we don't expect anyone
     * to insert any domains after us....
     *
     * Note that we may still crash afterwards, as we may not properly
     * check that all data structures are dereferenced etc...
     */
    int error = 0;
    
    mtx_lock(&dom_mtx);
    if (domains != &psdomain) {
	PS_PRINTF(PS_DEBUG_SOCKET | PS_DEBUG_ERROR, 
		  "Improper protocol insertion order.  Failed.\n");
	error = EBUSY;
	goto done;
    }

    domains = domains->dom_next;

done:
    mtx_unlock(&dom_mtx);
    return error;
#endif
}
