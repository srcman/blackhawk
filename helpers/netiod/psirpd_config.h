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

#ifndef _PSIRP_CONFIG_H_
#define _PSIRP_CONFIG_H_

/** Interface configuration */

struct config_if_list_item {
    LIST_ENTRY(config_if_list_item) entries;
    char if_name[IF_NAMESIZE];      /* Interface name, e.g. em0 */
    psirp_fid_t bf_def; /* Default "route" per iface */
    psirp_fid_t bf;
    u_int8_t  def_exists;
};

typedef struct config_if_list_item config_if_list_item_t;


psirp_error_t psirpd_config_init(char *cfg_file);
void psirpd_config_set_value(config_if_list_item_t*, char*, char*);
config_if_list_item_t * psirpd_config_iface_exists(char *);
psirp_fid_t * psirpd_config_get_bf(char *);
psirp_fid_t * psirpd_config_get_def();
int psirpd_config_hextoint(char);
int psirpd_config_ok();


LIST_HEAD(config_if_list, config_if_list_item) config_if_list_head;


#endif /* PSIRPD_CONFIG_H */
