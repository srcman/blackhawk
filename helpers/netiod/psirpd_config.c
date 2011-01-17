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

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/param.h>
#include <libpsirp.h>

#include "psirp_common_types.h"
#include "../../libpsirp/src/psirp_debug.h"
#include "../../libpsirp/src/psirp_old.h"
#include "psirpd_config.h"



//static struct psirpd_config config;
int config_file_ok = 0;


psirp_error_t
psirpd_config_init(char *cfg_file){

    char *line = NULL;
    int n;
    char *sep = ";", *name = NULL, *bf_str = NULL, *bf_type = NULL;
    config_if_list_item_t *cf_list_entry = NULL;
    

    ENTER();
    LIST_INIT(&config_if_list_head);

    /* Read the configuration file, put interfaces to list */

    FILE *f = fopen (cfg_file,"r");
    if ( NULL == f ) {
        return PSIRP_FAIL_FILEREADERROR;
    }

    config_file_ok=1;

    /* PJ: Read the line from the file, "name;lid|def;bf" */
    n = PSIRP_FID_LEN * 8 + IF_NAMESIZE + 16; /* XXX define correct size */
    line = (char *)malloc( n * sizeof(char));
    while(NULL!=fgets(line,n,f)) {
        if(line[0]=='#' || line[0]==' ' || line[0]=='\n')
            continue;
        name=strtok(line,sep);
        /* Check if iface already exists */
        if( (cf_list_entry = psirpd_config_iface_exists(name)) != NULL) {
            bf_type = strtok (NULL, sep);
            bf_str = strtok (NULL, sep);
            psirpd_config_set_value(cf_list_entry, bf_type, bf_str);
            /* read type, value */
            /* modify the existing entry */
        } else {
            PSIRP_MALLOC(cf_list_entry, sizeof (config_if_list_item_t));
            memset(cf_list_entry, 0, sizeof(config_if_list_item_t));

            strcpy(cf_list_entry->if_name,name);
        
            /* XXX  Supports only one BF per iface at the moment, this 
               must be changed for LITs later*/
            bf_type = strtok(NULL, sep);  /* get type (lid, def,...) */
            bf_str = strtok(NULL, sep);   /* get bf */
            psirpd_config_set_value(cf_list_entry, bf_type, bf_str);
            LIST_INSERT_HEAD(&config_if_list_head, cf_list_entry, entries);
        }
    }
    
    return PSIRP_OK;
}

void
psirpd_config_set_value(config_if_list_item_t *item, char *type, char *value) {
    /* Do we need some checking here??? */

    u_int8_t byte;
    int i,j;
    char mystr[3] = {0};

    u_int8_t *mybyte;



    if((strlen(value)-1)*4 == 8*PSIRP_FID_LEN) {
        if(strcmp(type, "lid") == 0 ) {
            for (j=0; j < 4; j++) {
                mybyte = (u_int8_t *)&item->bf.id[j*8];
                for (i=0; i < 16; i+=2 ) {
                    mystr[0] = *(value+(j*16+i));
                    mystr[1] = *(value+(j*16+i+1));
                    byte = (u_int8_t)(strtol(mystr, NULL, 16) & 0xFF);
                    
                    *mybyte++ = byte;
                }
            }
            PSIRP_DEBUG_HEXDUMP(&item->bf.id[0] ,PSIRP_FID_LEN, 
                                "LID ADDED TO LIST"); 
        } else if (strcmp(type, "def") == 0 ) {
            for (j=0; j < 4; j++) {
                mybyte = (uint8_t *)&item->bf_def.id[j*8];
                for (i=0; i < 16; i+=2 ) {
                    mystr[0] = *(value+(j*16+i));
                    mystr[1] = *(value+(j*16+i+1));
                    byte = (u_int8_t)(strtol(mystr, NULL, 16) & 0xFF);
                    
                    *mybyte = byte;
                    mybyte++;
                }
            }
            PSIRP_DEBUG_HEXDUMP(&item->bf_def.id[0] ,PSIRP_FID_LEN, 
                                "DEFAULT ROUTE ADDED TO LIST"); 
            item->def_exists=1;
        }
    } else {
        /* bf_str is wrong size */
    }
}



config_if_list_item_t *
psirpd_config_iface_exists(char *ifn) {
    config_if_list_item_t *ifitem;
    LIST_FOREACH(ifitem, &config_if_list_head, entries) {
        if (strcmp(ifitem->if_name, ifn) == 0) { /* XXX */
            return ifitem;
        }
    }
    return NULL;
}


psirp_fid_t *
psirpd_config_get_bf(char *ifn) {
    config_if_list_item_t *ifitem;
    LIST_FOREACH(ifitem, &config_if_list_head, entries) {
        if ( strcmp (ifitem->if_name, ifn) == 0 ) /* XXX */
            return &ifitem->bf;
    }
    return NULL;
}

psirp_fid_t *
psirpd_config_get_def() {
    config_if_list_item_t *ifitem;
    /* PJ: It is assumed that if we find ONE default route, it is 
       always the correct one :-) You can put multiple default routes
       to different interfaces in the configuration file, but they
       should be all the same */

    LIST_FOREACH(ifitem, &config_if_list_head, entries) {
        if (ifitem->def_exists) {
            PSIRP_DEBUG_HEXDUMP(&ifitem->bf_def.id[0] ,PSIRP_FID_LEN, 
                                "The default route found in the list"); 

            return &ifitem->bf_def;
        }
    }
    return NULL;
}

int
psirpd_config_ok() {
    return config_file_ok;
}
