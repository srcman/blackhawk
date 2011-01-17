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

/* XXX: Scope R/W access */

%include "../../psfs/module/ps_scope.h"

%inline %{
PyObject * psirp_py_data_to_scope(caddr_t data) {
    struct ps_scope_dat_page *sdp = NULL;
    int count, i;
    PyObject *scopeobj = NULL;
    PyGILState_STATE gstate;
    int err = 0;
    
    ENTER();
    gstate = PyGILState_Ensure();
    
    sdp = (struct ps_scope_dat_page *)data;
    count = sdp->sdp_id_count;
    PSIRP_DEBUG(PSIRP_DBG_GARB, "%d RIds", count);
    if (count < 0) {
	goto psirp_py_data_to_scope__return;
    }
    
    scopeobj = PyTuple_New(count);
    if (NULL == scopeobj) {
	goto psirp_py_data_to_scope__return;
    }
    
    for (i = 0; i < count; i++) {
	PyObject *ridobj;
	
        ridobj = PyBuffer_FromMemory(sdp->sdp_entries[i].id,
                                     sizeof(sdp->sdp_entries[0].id));
	
        err = PyTuple_SetItem(scopeobj, i, ridobj);
	if (err) {
	    Py_DECREF(scopeobj);
	    goto psirp_py_data_to_scope__return;
	}
    }
    
psirp_py_data_to_scope__return:
    PyGILState_Release(gstate);
    RETURN(scopeobj);
}

PyObject * psirp_py_scope(psirp_pub_t pub) {
    return psirp_py_data_to_scope(psirp_pub_data(pub));
}

void psirp_py_scope_init(psirp_pub_t scope_pub) {
    
    caddr_t scope_data;
    u_int64_t data_len;
    struct ps_scope_dat_page *sdp;
    struct ps_meta *meta;
    
    static psirp_id_t ps_sdp_magic = { PS_SDP_MAGIC_INIT };
    
    scope_data = psirp_pub_data(scope_pub);
    data_len = psirp_pub_data_len(scope_pub);    
    if (NULL == scope_pub || NULL == scope_data
	|| sizeof(struct ps_scope_dat_page) > data_len) {
	
	return; /* XXX */
    }
    
    sdp = (struct ps_scope_dat_page *)scope_data;
    
    memset(sdp, 0, sizeof(struct ps_scope_dat_page));
    
    /* Set magic value */
    sdp->sdp_magic = ps_sdp_magic;
    
    /* Sett publication type */
    meta = PSFS_PUB_META(scope_pub);
    meta->pm_type = PS_PUB_SCOPE;
}

#if 0
struct ps_scope_dat_page * psirp_py_data_to_ps_scope_dat_page(caddr_t data) {
    struct ps_scope_dat_page *sdp = NULL;
    PyGILState_STATE gstate;
    
    ENTER();
    gstate = PyGILState_Ensure();
    
    sdp = (struct ps_scope_dat_page *)data;
    
    PyGILState_Release(gstate);
    RETURN(sdp);
}
#endif
%}


/* XXX: Event page access */

%include "../../psfs/module/ps_event.h"

%extend ps_event_page {
    ps_event_page() {
	struct ps_event_page *pep = NULL;
	
	pep = (struct ps_event_page *)malloc(sizeof(struct ps_event_page));
	if (!pep)
	    return NULL;
	memset(pep, 0, sizeof(struct ps_event_page));
	
	return pep;
    }
    
    ~ps_event_page() {
	free($self);
    }
};

%inline %{
PyObject * psirp_py_read_event_page(int fd, struct ps_event_page *pep) {
    int n, count, i;
    PyObject *pageobj = NULL;
    PyGILState_STATE gstate;
    int err = 0;
    
    ENTER();
    gstate = PyGILState_Ensure();
    
    lseek(fd, 0, SEEK_SET);
    n = read(fd, pep, sizeof(*pep));
    if (n < 0) {
        PyErr_SetFromErrno(PyExc_IOError);
    }
    else if (n > 0) {
	count = pep->pep_count;
	PSIRP_DEBUG(PSIRP_DBG_GARB, "%d events", count);
	if (count < 0) {
	    goto psirp_py_read_event_page__return;
	}
	
	pageobj = PyTuple_New(count);
	if (NULL == pageobj) {
	    goto psirp_py_read_event_page__return;
	}
	
	for (i = 0; i < count; i++) {
	    PyObject *eventobj = NULL, *sidobj, *ridobj, *flagsobj;
	    
	    eventobj = PyTuple_New(3);
	    if (NULL == eventobj) {
		goto psirp_py_read_event_page__err;
	    }
	    
	    sidobj = PyBuffer_FromMemory(pep->pep_events[i].pe_sid.id,
					 sizeof(pep->pep_events[i].pe_sid.id));
	    err = PyTuple_SetItem(eventobj, 0, sidobj);
	    if (err) {
		Py_DECREF(eventobj);
		eventobj = NULL;
		goto psirp_py_read_event_page__err;
	    }

	    ridobj = PyBuffer_FromMemory(pep->pep_events[i].pe_rid.id,
					 sizeof(pep->pep_events[i].pe_rid.id));
	    err = PyTuple_SetItem(eventobj, 1, ridobj);
	    if (err) {
		Py_DECREF(eventobj);
		eventobj = NULL;
		goto psirp_py_read_event_page__err;
	    }
	    
            flagsobj = PyInt_FromLong(pep->pep_events[i].pe_flags);
            err = PyTuple_SetItem(eventobj, 2, flagsobj);
            if (err) {
                Py_DECREF(eventobj);
                flagsobj = NULL;
                goto psirp_py_read_event_page__err;
            }
            
	    err = PyTuple_SetItem(pageobj, i, eventobj);
	    if (err) {
		goto psirp_py_read_event_page__err;
	    }
	}
    }

psirp_py_read_event_page__return:
    PyGILState_Release(gstate);
    RETURN(pageobj);
psirp_py_read_event_page__err:
    Py_DECREF(pageobj);
    pageobj = NULL;
    PyGILState_Release(gstate); 
    RETURN(pageobj);
}
%}
