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

%module libpsirp_rb
%{
#include <sys/param.h>
#include "../include/libpsirp.h"

/* XXX: kernel events */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/errno.h>
%}

typedef unsigned long u_int64_t;
typedef void * psirp_pub_t;
typedef void * caddr_t;

%typemap(in) psirp_id_t * {
    struct RString *rs;
    int id_len;

    rs = RSTRING($input);
    
    $1 = ($1_ltype)malloc(sizeof($*1_ltype));
    id_len = sizeof(*$1);
    bzero($1, id_len);
    memcpy($1, rs->ptr, (rs->len < id_len) ? rs->len : id_len); /* XXX */
}
%typemap(freearg) psirp_id_t *, psirp_id_t * {
    if ($1) {
        free($1);
        $1 = NULL;
    }
}

%typemap(out) psirp_id_t * {
    VALUE v = rb_str_new((char *)$1, sizeof(*$1)); /* XXX: Does a memcpy. */
    $result = SWIG_Ruby_AppendOutput($result, v);
}

%typemap(in, numinputs=0) psirp_pub_t * {
    $1 = ($1_ltype)malloc(sizeof($*1_ltype));
    memset($1, 0, sizeof($*1_ltype));
}
%typemap(argout) psirp_pub_t * {
    VALUE v = SWIG_NewPointerObj(SWIG_as_voidptr(*$1),
                                 $descriptor(psirp_pub_t),
                                 0);
    $result = SWIG_Ruby_AppendOutput($result, v);
}
%typemap(freearg) psirp_pub_t * {
    if ($1) {
        free($1);
        $1 = NULL;
    }
}

%inline %{

VALUE psirp_rb_atoid(const char *a) {
    VALUE id_rs;
    char *id_rs_ptr;
    
    id_rs = rb_str_new(NULL, PSIRP_ID_LEN);
    id_rs_ptr = RSTRING(id_rs)->ptr;
    
    psirp_atoid((psirp_id_t *)id_rs_ptr, a);
    
    return id_rs;
}

#if 0
/*
 * XXXX: We wouldn't want to copy publication data, but if we just
 *       create a string that points to a publication's data, Ruby's
 *       garbage collector will eventually try to free it. In other
 *       words, the code below does not work. Maybe there could be
 *       another way of creating an object that can be accessed like a
 *       string...
 */
VALUE psirp_rb_data_to_buffer(caddr_t data, u_int64_t len) {
    /* XXXX */

    NEWOBJ(str, struct RString);
    OBJSETUP(str, rb_cString, T_STRING);

    str->ptr = data;
    str->len = len;
    str->aux.capa = len;
    
    OBJ_TAINT(str);
    OBJ_FREEZE(str);
    
    return (VALUE)str;
}

VALUE psirp_rb_buffer(psirp_pub_t pub) {
    return psirp_rb_data_to_buffer(psirp_pub_data(pub),
                                   psirp_pub_data_len(pub));
}
#endif

VALUE psirp_rb_pub_to_string(psirp_pub_t pub) {
    /* XXX */
    
    caddr_t data;
    u_int64_t len;
    
    data = psirp_pub_data(pub);
    len = psirp_pub_data_len(pub);

    return rb_tainted_str_new(data, len); /* XXX: Does a memcpy. */
}

psirp_pub_t psirp_rb_publish_string(psirp_id_t *sid, psirp_id_t *rid,
                                    VALUE str) {
    /* XXX */

    struct RString *rs;
    psirp_pub_t pub;

    rs = RSTRING(str);

    psirp_create(rs->len, &pub);
    memcpy(psirp_pub_data(pub), rs->ptr, rs->len); /* XXX */
    psirp_publish(sid, rid, pub);

    return pub;
}

int psirp_rb_subscribe_sync(psirp_id_t *sid, psirp_id_t *rid,
                            psirp_pub_t *pubp, VALUE timeout) {
    struct timeval to, *to_p;
    
    if (NIL_P(timeout)) {
        //printf("timeout is nil\n");
        to_p = NULL;
    }
    else {
        //printf("timeout is 0x%lx\n", timeout);
        long msec = NUM2LONG(timeout);
        //printf("timeout is %ld ms\n", msec);
        
        memset(&to, 0, sizeof(to));
        to_p = &to;
        
        if (msec != 0) {
            long sec = msec/1000;
            long usec = (msec-(sec*1000))*1000;
            
            to.tv_sec = (time_t)sec;
            to.tv_usec = (suseconds_t)usec;
        }
    }
    
    return psirp_subscribe_sync(sid, rid, pubp, to_p);
}

static VALUE _psirp_rb_get_rids(psirp_pub_t pub,
                                enum psirp_pub_type rq_type) {
    psirp_id_t *rids = NULL;
    int rid_count = 0;
    int err = 0;
    VALUE rid_ary_obj = Qnil;
    int i;

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
        return Qnil;
    }
    
    if (err != 0 || rid_count < 0 || rids == NULL) {
	return Qnil;
    }
    
    rid_ary_obj = rb_ary_new2(rid_count);
    
    for (i = 0; i < rid_count; i++) {
	VALUE rid_obj;
	
        /* XXX: A memcpy is done for each string. */
        rid_obj = rb_tainted_str_new(rids[i].id, sizeof(rids[0].id));
        rb_str_freeze(rid_obj);
	
        rb_ary_store(rid_ary_obj, i, rid_obj);
    }
    
    rb_ary_freeze(rid_ary_obj);
    
    return rid_ary_obj;
}

VALUE psirp_rb_scope_get_rids(psirp_pub_t pub) {
    return _psirp_rb_get_rids(pub, PS_PUB_SCOPE);
}

VALUE psirp_rb_pub_get_vrids(psirp_pub_t pub) {
    return _psirp_rb_get_rids(pub, PS_PUB_DATA);
}

VALUE psirp_rb_version_get_prids(psirp_pub_t pub) {
    return _psirp_rb_get_rids(pub, PS_PUB_VERSION);
}

%}

%constant int PSIRP_ID_LEN   = PSIRP_ID_LEN;
%constant int NOTE_PUBLISH   = NOTE_PUBLISH;
%constant int NOTE_SUBSCRIBE = NOTE_SUBSCRIBE;

%include "../include/libpsirp.h"

%include libpsirp_event.i
