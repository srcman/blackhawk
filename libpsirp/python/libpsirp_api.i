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

%inline %{

static PyObject * _psirp_py_data_to_buffer(caddr_t data, u_int64_t len) {
    return PyBuffer_FromReadWriteMemory(data, len);
}

PyObject * psirp_py_buffer(psirp_pub_t pub) {
    return _psirp_py_data_to_buffer(psirp_pub_data(pub),
                                    psirp_pub_data_len(pub));
}

enum psirp_pub_type psirp_py_type(psirp_pub_t pub) {
    return psirp_pub_type(pub);
}

#if 0
int psirp_py_subscribe_sync_(psirp_id_t *sid, psirp_id_t *rid,
			     psirp_pub_t *pubp, double timeout) {
    
    struct timeval tv_timeout, *tv_timeout_p;
    long sec, usec;
    
    PyGILState_STATE gstate;
    PyOS_sighandler_t oldh;
    int err;
    
    if (timeout < 0) {
	tv_timeout_p = NULL;
    }
    else {
	sec = (long)timeout;
	usec = (long)((timeout-sec)*1000000);
	
	memset(&tv_timeout, 0, sizeof(tv_timeout));
	tv_timeout.tv_sec = (time_t)sec;
	tv_timeout.tv_usec = (suseconds_t)usec;	
	
	tv_timeout_p = &tv_timeout;
    }
    
    gstate = PyGILState_Ensure();
    Py_BEGIN_ALLOW_THREADS;
    /* XXX: Causes segfaults. */
    err = psirp_subscribe_sync(sid, rid, pubp, tv_timeout_p);
    Py_END_ALLOW_THREADS;
    PyGILState_Release(gstate);
    return err;
}
#endif

PyObject * psirp_py_atoid(const char *str) {
    PyObject *id;
    char *buf;
    
    id = PyString_FromStringAndSize(NULL, PSIRP_ID_LEN);
    buf = PyString_AsString(id);
    psirp_atoid((psirp_id_t *)buf, str);
    
    return id;
}

static PyObject * _psirp_py_get_rids(psirp_pub_t pub,
                                     enum psirp_pub_type rq_type,
                                     int index) {
    PyGILState_STATE gstate;
    psirp_id_t *rids = NULL;
    int rid_count = 0;
    int err = 0;
    PyObject *rid_tuple_obj = NULL;
    int i;
        
    gstate = PyGILState_Ensure();

    switch (rq_type) {
        /* Note: rq_type can be different than the type of pub. */
    case PS_PUB_SCOPE:
        err = psirp_scope_get_rids(pub, &rids, &rid_count);
        break;
    case PS_PUB_DATA:
        err = psirp_pub_get_vrids(pub, &rids, &rid_count);
        break;
    case PS_PUB_VERSION:
        err = psirp_version_get_prids(pub, &rids, &rid_count);
        break;
    default:
        goto psirp_py_get_rids__return;
    }
    
    if (err != 0 || rid_count < 0 || rids == NULL) {
	goto psirp_py_get_rids__return;
    }
    
    if (index < 0) {
        goto psirp_py_get_rids__return;
    }
    else if (index > rid_count) {
        index = rid_count;
    }
    
    rid_tuple_obj = PyTuple_New(rid_count-index);
    if (NULL == rid_tuple_obj) {
	goto psirp_py_get_rids__return;
    }
    
    for (i = index; i < rid_count; i++) {
	PyObject *rid_obj;
	
        rid_obj = PyBuffer_FromMemory(rids[i].id, sizeof(rids[0].id));
	
        err = PyTuple_SetItem(rid_tuple_obj, i-index, rid_obj);
	if (err) {
	    Py_DECREF(rid_tuple_obj);
            rid_tuple_obj = NULL;
            goto psirp_py_get_rids__return;
	}
    }
    
psirp_py_get_rids__return:
    PyGILState_Release(gstate);
    return rid_tuple_obj;
}

PyObject * psirp_py_scope_get_rids(psirp_pub_t pub, int index) {
     return _psirp_py_get_rids(pub, PS_PUB_SCOPE, index);
}

PyObject * psirp_py_pub_get_vrids(psirp_pub_t pub, int index) {
     return _psirp_py_get_rids(pub, PS_PUB_DATA, index);
}

PyObject * psirp_py_version_get_prids(psirp_pub_t pub, int index) {
     return _psirp_py_get_rids(pub, PS_PUB_VERSION, index);
}

%}


%include "../../psfs/module/ps.h"
%include "../include/libpsirp.h"


%inline %{
void psirp_py_debug_print_(int level, const char* file, const char *func,
			   const char *msg) {
//#ifdef DEBUG
    psirp_debug_print(level, file, func, (char *)msg);
//#else
//#endif
}

void psirp_py_debug_enter_(const char* file, const char* func, int lineno) {
//#ifdef DEBUG
    psirp_debug_print(PSIRP_DBG_FNCE, file, func,
		      "%s(%d): ENTER\n", file, lineno);
//#else
//#endif
}

PyObject * psirp_py_debug_return_(const char* file,
                                  const char* func,
                                  int lineno,
                                  PyObject *retval) {
//#ifdef DEBUG
    psirp_debug_print(PSIRP_DBG_FNCE, file, func,
		      "%s(%d): RETURN\n", file, lineno);
//#else
//#endif
    Py_XINCREF(retval); /* XXX: This clearly seems to be needed - but why? */
    return retval;
}
%}

%include "../src/psirp_debug.h"
