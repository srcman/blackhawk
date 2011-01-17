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
#ifndef LIBPSIRP_H
#define LIBPSIRP_H
#include <sys/types.h>
#include <sys/event.h>
#include <ps.h>

enum psirp_pub_type { PSIRP_PUB_UNINITIALIZED=0, PSIRP_PUB_UNKNOWN,
                      PSIRP_PUB_SCOPE, PSIRP_PUB_DATA };
typedef enum psirp_pub_type psirp_pub_type_t;


int psirp_create(u_int64_t len, psirp_pub_t *pub);
int psirp_publish(psirp_id_t *sid, psirp_id_t *rid, psirp_pub_t pub);
int psirp_subscribe(psirp_id_t *sid, psirp_id_t *rid, psirp_pub_t *pubp);
int psirp_subscribe_scope(psirp_id_t *sid, psirp_pub_t *pub);
int psirp_subscribe_sync(psirp_id_t *sid, psirp_id_t *rid, psirp_pub_t *pubp,
                         struct timeval *timeout);
int psirp_free(psirp_pub_t pub);
int psirp_status(char **output);

int psirp_subscribe_with_flags(psirp_id_t *sid, psirp_id_t *rid,
                               psirp_pub_t *pubp, ps_flags_t flags);
int psirp_subscribe_sync_with_flags(psirp_id_t *sid, psirp_id_t *rid,
                                    psirp_pub_t *pubp, struct timeval *timeout,
                                    ps_flags_t flags);

/* Accessors */
caddr_t psirp_pub_data(psirp_pub_t pub);
u_int64_t psirp_pub_data_len(psirp_pub_t pub);
psirp_id_t *psirp_pub_sid(psirp_pub_t pub);
psirp_id_t *psirp_pub_rid(psirp_pub_t pub);
psirp_id_t *psirp_pub_current_version(psirp_pub_t pub);
int psirp_pub_fd(psirp_pub_t pub);
psirp_pub_type_t psirp_pub_type(psirp_pub_t pub);

/* XXX accessors */
int psirp_pub_current_version_index(psirp_pub_t pub);
int psirp_pub_version_count(psirp_pub_t pub);
int psirp_scope_rid_count(psirp_pub_t scope);
int psirp_scope_get_rids(psirp_pub_t scope,
                         psirp_id_t **rids, int *rid_count);
int psirp_pub_get_vrids(psirp_pub_t pub,
                        psirp_id_t **rids, int *rid_count);
int psirp_version_get_prids(psirp_pub_t version,
                            psirp_id_t **rids, int *rid_count);
int psirp_subscribe_versions(psirp_pub_t pub,
                             psirp_pub_t *versions,
                             int start_index,
                             int max_count);

/* Mutators */
void psirp_pub_set_data(psirp_pub_t pub, caddr_t dptr);

/* Helpers */
int psirp_atoid(psirp_id_t *rid, const char *str);
char *psirp_idtoa(psirp_id_t *rid); /* non-reentrant (static return value)*/
void psirp_debug_meta(psirp_pub_t pub);
void psirp_debug_meta2(psirp_pub_t pub);
int psirp_atoids(psirp_id_t *sid, psirp_id_t *rid, const char *str);
char *psirp_idstoa(psirp_id_t *sid, psirp_id_t *rid);
int psirp_idcmp(psirp_id_t *id1, psirp_id_t *id2);
void psirp_idzero(psirp_id_t *id);
void psirp_idinc(psirp_id_t *idp);



/* kqueue */



/* by default grow kevent list by 3 kevents (java vector style)*/
#define PSIRP_DEFAULT_GROWSIZE 3

struct psirp_event {
    psirp_pub_t pub;
    u_int32_t flags;
    u_int32_t cb_retcode;
};

typedef int (*psirp_callback_t)(struct psirp_event *, void *opaque);

struct psirp_kq_handle {
    int kq;
    struct psirp_kevent_list *slh_first;  /* root node */
    int size_evlist;
    struct timespec timeout;
};

typedef struct psirp_kq_handle psirp_kq_t;

struct psirp_kevent_list {
    struct kevent event;
    psirp_callback_t callback;
    void *opaque;
#ifndef SWIG
    SLIST_ENTRY(psirp_kevent_list) next;
#endif
};

typedef struct psirp_kevent_list psirp_kevl_t;        



struct psirp_kq_handle *psirp_create_kq(void);
void psirp_delete_kq(struct psirp_kq_handle *ph);

int psirp_wait_kq(struct psirp_kq_handle *ph, int max_secs,
		  struct psirp_event *events, int *num_events);
int
psirp_add_kq_listener(psirp_kq_t *kh, psirp_pub_t pub, int filter,
                      psirp_callback_t callback, void *opaque);
#endif
