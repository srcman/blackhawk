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

/* XXX: IPC */

%include "../../helpers/netiod/psirpd_hdrs.h"

%extend psirpd_hdrs_metadata {
    psirpd_hdrs_metadata() {
	struct psirpd_hdrs_metadata *data = NULL;
	
	data = (struct psirpd_hdrs_metadata *) \
	    malloc(sizeof(psirpd_hdrs_metadata_t));
	if (!data)
	    return NULL;	
	memset(data, 0, sizeof(psirpd_hdrs_metadata_t));
	
	return data;
    }
    
    ~psirpd_hdrs_metadata() {
	free($self);
    }
    
    psirp_id_t * getsid() {
	return (&$self->sid);
    }
    
    psirp_id_t * getrid() {
	return (&$self->rid);
    }
    
    psirp_id_t * getvrid() {
	return (&$self->vrid);
    }
    
    psirp_id_t * getfid() {
	return (psirp_id_t *)(&$self->fid);
    }
    
    void setsid(psirp_id_t *sid) {
	memcpy(&$self->sid, sid, sizeof(psirp_id_t));
    }
    
    void setrid(psirp_id_t *rid) {
	memcpy(&$self->rid, rid, sizeof(psirp_id_t));
    }
    
    void setvrid(psirp_id_t *vrid) {
	memcpy(&$self->vrid, vrid, sizeof(psirp_id_t));
    }
    
    void setfid(psirp_id_t *fid) {
	memcpy(&$self->fid, fid, sizeof(psirp_id_t));
    }

    char * __str__() {
        static char md_str[1024]  = { 0 };
        
        char sidrid_str[ 2 * (2*PSIRP_ID_LEN) + 2] = { 0 };
        char vrid_str[   2 * PSIRP_ID_LEN     + 1] = { 0 };
        char fid_str[    2 * PSIRP_ID_LEN     + 1] = { 0 };
        
        struct psirpd_hdrs_metadata *md_hdr = $self;
        
        memcpy(sidrid_str, psirp_idstoa(&md_hdr->sid, &md_hdr->rid),
               sizeof(sidrid_str));
        memcpy(vrid_str, psirp_idtoa(&md_hdr->vrid),
               sizeof(vrid_str));
        memcpy(fid_str, psirp_idtoa(&md_hdr->fid),
               sizeof(fid_str));
        
        snprintf(md_str, 1024,
                 "         SId/RId: %s\n" \
                 "         vRId:    %s\n" \
                 "         FId:     %s\n" \
                 "         len:     %lu\n" \
                 "         type:    0x%x\n" \
                 "         flags:   0x%02x\n",
                 sidrid_str,
                 vrid_str,
                 fid_str,
                 md_hdr->len,
                 md_hdr->rzvhdr_type,
                 md_hdr->flags);
        
        return md_str;
    }
}

%inline %{
psirp_pub_t psirp_py_create_md_pub(struct psirpd_hdrs_metadata *data) {
    psirp_pub_t pub = NULL;
    
    ENTER();
    
    if (psirp_create(sizeof(psirpd_hdrs_metadata_t), &pub)) {
	return (void *)PyErr_SetFromErrno(PyExc_EnvironmentError);
    }
    
    if (data && (void *)data != Py_None) {
	memcpy(psirp_pub_data(pub), data, psirp_pub_data_len(pub));
    }
    else {
	memset(psirp_pub_data(pub), 0, psirp_pub_data_len(pub));
    }
    
    RETURN(pub);
}

struct psirpd_hdrs_metadata *psirp_py_buf_hdrs_metadata(PyObject *bufobj) {
    ENTER();
    
    if (PyBuffer_Check(bufobj)) {
	void *buf = NULL;
	long len = 0;
	
        PyObject_AsReadBuffer(bufobj, (const void **)&buf, &len);
	
	if (len >= sizeof(psirpd_hdrs_metadata_t)) {
	    RETURN((struct psirpd_hdrs_metadata *)buf);
	}
    }
    
    RETURN(NULL);
}

struct psirpd_hdrs_metadata *psirp_py_pub_hdrs_metadata(psirp_pub_t pub) {
    ENTER();
    
    if (pub && (void *)pub != Py_None
	&& psirp_pub_data_len(pub) >= sizeof(psirpd_hdrs_metadata_t)) {
	RETURN((struct psirpd_hdrs_metadata *)psirp_pub_data(pub));
    }
    else {
	RETURN(NULL);
    }
}
%}


%include "../../helpers/netiod/psirpd_ipc.h"

%extend psirpd_ipc_hdrs_metadata_ext {
    psirpd_ipc_hdrs_metadata_ext() {
	struct psirpd_ipc_hdrs_metadata_ext *data = NULL;
	
	data = (struct psirpd_ipc_hdrs_metadata_ext *) \
	    malloc(sizeof(psirpd_ipc_hdrs_metadata_ext_t));
	if (!data)
	    return NULL;	
	memset(data, 0, sizeof(psirpd_ipc_hdrs_metadata_ext_t));
	
	return data;
    }
    
    ~psirpd_ipc_hdrs_metadata_ext() {
	free($self);
    }
    
    psirp_id_t * getsid() {
	return (&$self->md_hdr.sid);
    }
    
    psirp_id_t * getrid() {
	return (&$self->md_hdr.rid);
    }

    psirp_id_t * getvrid() {
	return (&$self->md_hdr.vrid);
    }
    
    psirp_id_t * getfid() {
	return (psirp_id_t *)(&$self->md_hdr.fid);
    }
    
    void setsid(psirp_id_t *sid) {
	memcpy(&$self->md_hdr.sid, sid, sizeof(psirp_id_t));
    }
    
    void setrid(psirp_id_t *rid) {
	memcpy(&$self->md_hdr.rid, rid, sizeof(psirp_id_t));
    }

    void setvrid(psirp_id_t *vrid) {
	memcpy(&$self->md_hdr.vrid, vrid, sizeof(psirp_id_t));
    }
    
    void setfid(psirp_id_t *fid) {
	memcpy(&$self->md_hdr.fid, fid, sizeof(psirp_id_t));
    }
    
    psirp_id_t * getextfid() {
	return (psirp_id_t *)(&$self->md_ext.fid);
    }
    
    void setextfid(psirp_id_t *fid) {
	memcpy(&$self->md_ext.fid, fid, sizeof(psirp_id_t));
    }
    
    char * __str__() {
        static char md_str[1024]  = { 0 };
        
        char sidrid_str[ 2 * (2*PSIRP_ID_LEN) + 2] = { 0 };
        char vrid_str[   2 * PSIRP_ID_LEN     + 1] = { 0 };
        char fid_str[    2 * PSIRP_ID_LEN     + 1] = { 0 };
        char ext_fid_str[2 * PSIRP_ID_LEN     + 1] = { 0 };
        
        struct psirpd_hdrs_metadata    *md_hdr = &$self->md_hdr;
        struct psirpd_ipc_metadata_ext *md_ext = &$self->md_ext;
        
        memcpy(sidrid_str, psirp_idstoa(&md_hdr->sid, &md_hdr->rid),
               sizeof(sidrid_str));
        memcpy(vrid_str, psirp_idtoa(&md_hdr->vrid),
               sizeof(vrid_str));
        memcpy(fid_str, psirp_idtoa(&md_hdr->fid),
               sizeof(fid_str));
        memcpy(ext_fid_str, psirp_idtoa(&md_ext->fid),
               sizeof(ext_fid_str));
        
        snprintf(md_str, 1024,
                 "         SId/RId: %s\n" \
                 "         vRId:    %s\n" \
                 "         FId:     %s\n" \
                 "         len:     %lu\n" \
                 "         type:    0x%x\n" \
                 "         flags:   0x%02x\n" \
                 "         -----------\n" \
                 "         FId:     %s\n" \
                 "         relay:   %d\n",
                 sidrid_str,
                 vrid_str,
                 fid_str,
                 md_hdr->len,
                 md_hdr->rzvhdr_type,
                 md_hdr->flags,
                 ext_fid_str,
                 md_ext->relay);
        
        return md_str;
    }
}

%inline %{
psirp_pub_t psirp_py_create_md_ext_pub(struct psirpd_ipc_hdrs_metadata_ext *data) {
    psirp_pub_t pub = NULL;
    
    ENTER();
    
    if (psirp_create(sizeof(psirpd_ipc_hdrs_metadata_ext_t), &pub)) {
	return (void *)PyErr_SetFromErrno(PyExc_EnvironmentError);
    }
    
    if (data && (void *)data != Py_None) {
	memcpy(psirp_pub_data(pub), data, psirp_pub_data_len(pub));
    }
    else {
	memset(psirp_pub_data(pub), 0, psirp_pub_data_len(pub));
    }
    
    RETURN(pub);
}

struct psirpd_ipc_hdrs_metadata_ext *psirp_py_buf_hdrs_metadata_ext(PyObject *bufobj) {
    ENTER();
    
    if (PyBuffer_Check(bufobj)) {
	void *buf = NULL;
	long len = 0;
	
        PyObject_AsReadBuffer(bufobj, (const void **)&buf, &len);
	
	if (len >= sizeof(psirpd_ipc_hdrs_metadata_ext_t)) {
	    RETURN((struct psirpd_ipc_hdrs_metadata_ext *)buf);
	}
    }
    
    RETURN(NULL);
}

struct psirpd_ipc_hdrs_metadata_ext *psirp_py_pub_hdrs_metadata_ext(psirp_pub_t pub) {
    ENTER();
    
    if (pub && (void *)pub != Py_None
	&& psirp_pub_data_len(pub) >= sizeof(psirpd_ipc_hdrs_metadata_ext_t)) {
	RETURN((struct psirpd_ipc_hdrs_metadata_ext *)psirp_pub_data(pub));
    }
    else {
	RETURN(NULL);
    }
}
%}




/* XXX: Sockets (mainly for testing network I/O in Python) */

%inline %{

#define PYTHON_RAW_SOCKETS_ENABLED 0 /* Disabled by default. */
#if PYTHON_RAW_SOCKETS_ENABLED

struct psirp_py_sockdata {
    int sock;
    int ifindex;
    struct sockaddr_dl dl;
};
typedef struct psirp_py_sockdata psirp_py_sockdata_t;

psirp_py_sockdata_t * psirp_py_sock_create(const char *ifname) {
    psirp_py_sockdata_t *sockdata = NULL;
    struct ifreq ifr;

    if (!ifname) {
        goto psirp_py_sock_create_fail;
    }

    sockdata = malloc(sizeof(psirp_py_sockdata_t));
    if (!sockdata) {
        goto psirp_py_sock_create_fail;
    }
    memset(sockdata, 0, sizeof(*sockdata));

    sockdata->sock = socket(AF_LINK, SOCK_DGRAM, 0);
    if (sockdata->sock == -1) {
        perror("socket()");
        goto psirp_py_sock_create_fail;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sockdata->sock, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl()");
        goto psirp_py_sock_create_fail;
    }
    sockdata->ifindex = ifr.ifr_index;

    sockdata->dl.sdl_len = sizeof(sockdata->dl) - sizeof(sockdata->dl.sdl_data);
    sockdata->dl.sdl_family = AF_LINK;
    sockdata->dl.sdl_index = sockdata->ifindex;

    if (bind(sockdata->sock,
             (struct sockaddr *)&sockdata->dl,
             sizeof(sockdata->dl)) == -1) {
        perror("bind()");
        goto psirp_py_sock_create_fail;
    }

    return sockdata;

psirp_py_sock_create_fail:
    if (sockdata) {
        free(sockdata);
    }
    return NULL;
}

void psirp_py_sock_close(psirp_py_sockdata_t *sockdata) {
    close(sockdata->sock);
    free(sockdata);
}

int psirp_py_sock_send(psirp_py_sockdata_t *sockdata, PyObject *obj) {
    void *buf = NULL;
    long len = 0;
    int r = -1;

    if (PyObject_AsReadBuffer(obj, (const void **)&buf, &len) == -1) {
        return -1;
    }

    r = sendto(sockdata->sock, buf, len, MSG_DONTROUTE | MSG_EOR,
               (struct sockaddr *)&sockdata->dl, sizeof(sockdata->dl));
    if (r == -1) {
        perror("sendto()");
    }
    
    return r;
}

/*
 * Note: the recv and read functions below do almost the same thing.
 */

PyObject * psirp_py_sock_recv(psirp_py_sockdata_t *sockdata,
                              PyObject *obj) {
    PyObject *bobj = Py_None,
             *robj = Py_None;
    void *buf = NULL;
    long len = 0;
    int dl_len = sizeof(sockdata->dl);
    int r = -1;

    if (PyBuffer_Check(obj)) {
        bobj = obj;
    }
    else if (PyInt_Check(obj) && (len = PyInt_AsLong(obj)) >= 0) {
        bobj = PyBuffer_New(len);
    }
    else {
        goto psirp_py_sock_recv_finish;
    }

    if (PyObject_AsWriteBuffer(bobj, &buf, &len) == -1) {
        bobj = Py_None; /* XXX: refcount */
        goto psirp_py_sock_recv_finish;
    }
    memset(buf, 0, len);

    r = recvfrom(sockdata->sock, buf, len, 0,
                 (struct sockaddr *)&sockdata->dl, &dl_len);
    if (r == -1) {
        perror("recvfrom()");
        bobj = Py_None; /* XXX: refcount */
        goto psirp_py_sock_recv_finish;
    }

psirp_py_sock_recv_finish:
    robj = PyTuple_New(2);
    PyTuple_SetItem(robj, 0, PyInt_FromLong(r));
    PyTuple_SetItem(robj, 1, bobj); /* XXX: refcount? */
    return robj;
}

PyObject * psirp_py_sock_read(int sock, PyObject *obj) {
    PyObject *bobj = Py_None,
             *robj = Py_None;
    void *buf = NULL;
    long len = 0;
    int r = -1;

    if (PyBuffer_Check(obj)) {
        bobj = obj;
    }
    else if (PyInt_Check(obj) && (len = PyInt_AsLong(obj)) >= 0) {
        bobj = PyBuffer_New(len);
    }
    else {
        goto psirp_py_sock_read_finish;
    }

    if (PyObject_AsWriteBuffer(bobj, &buf, &len) == -1) {
        bobj = Py_None; /* XXX: refcount */
        goto psirp_py_sock_read_finish;
    }
    memset(buf, 0, len);

    r = read(sock, buf, len);
    if (r == -1) {
        perror("read()");
        bobj = Py_None; /* XXX: refcount */
        goto psirp_py_sock_read_finish;
    }

psirp_py_sock_read_finish:
    robj = PyTuple_New(2);
    PyTuple_SetItem(robj, 0, PyInt_FromLong(r));
    PyTuple_SetItem(robj, 1, bobj); /* XXX: refcount? */
    return robj;
}

#endif /* PYTHON_RAW_SOCKETS_ENABLED */

%}

