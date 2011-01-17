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


#ifndef _PSIRPD_IPC_H
#define _PSIRPD_IPC_H


#ifndef SWIG
psirp_error_t psirpd_ipc_init(const char *, const char *);
void psirpd_ipc_cleanup();

psirp_error_t psirpd_ipc_set_next_ipc_local_pub(void);

psirp_error_t psirpd_ipc_local_regevents(int, int*);
psirp_error_t psirpd_ipc_local_next_regevents(int, int *);
psirp_error_t psirpd_ipc_local_unregevents(int);
psirp_error_t psirpd_ipc_local_handle_event(struct kevent *);

psirp_error_t psirpd_ipc_net_handle_metadata(psirpd_hdrs_metadata_t *);
psirp_error_t psirpd_ipc_net_handle_data(psirpd_hdrs_rzvhdr_t *,
					 void *, u_int64_t);
#endif /* SWIG */


struct psirpd_ipc_metadata_ext {
    psirp_fid_t fid;
    u_int8_t    relay;
};
typedef struct psirpd_ipc_metadata_ext psirpd_ipc_metadata_ext_t;

struct psirpd_ipc_hdrs_metadata_ext {
    psirpd_hdrs_metadata_t    md_hdr;
    psirpd_ipc_metadata_ext_t md_ext;
};
typedef struct psirpd_ipc_hdrs_metadata_ext psirpd_ipc_hdrs_metadata_ext_t;


#ifndef SWIG
char *psirpd_ipc_hdrs_metadata_ext_to_str(struct
                                          psirpd_ipc_hdrs_metadata_ext *);
#endif /* SWIG */


#endif /* PSIRPD_IPC_H */
