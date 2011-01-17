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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>

#include "ps.h"
#include "ps_debug.h"

void ps_debug_dump_meta_hdr(const char *str, void *meta) {
    ps_meta_t pm;
    
    u_int8_t *meta_hdr;
    int i, j, n;
    
    pm = (ps_meta_t)meta;
    
    meta_hdr = (u_int8_t *)&(pm->_pm_h);
    n = sizeof(struct ps_meta_hdr);
    
    if (NULL != str) {
        printf("%s:\n", str);
    }
    if (NULL == pm) {
        printf("NULL\n");
        return;
    }
    
    printf("%03d  ", (j=0));
    for (i = 0; i < n; i++) {
        printf("%02x ", meta_hdr[i]);
        if ((i+1) % 16 == 0 && (i+1) < n) {
            printf("\n%03d  ", ++j);
        }
    }
    printf("\n");
}

void ps_debug_print_meta_sub(const char *str, void *meta) {
    ps_meta_t pm;
    
    int i, j, i_p;
    psirp_id_t *idp;
    
    pm = (ps_meta_t)meta;
    
    i_p = 0;
    
    if (NULL != str) {
        printf("%s:\n", str);
    }
    if (NULL == pm) {
        printf("NULL\n");
        return;
    }
    
    for (i = 0; i < PS_META_SUB_OBJECT_COUNT; i++) {
        idp = &pm->pm_sub_object[i];
        for (j = 0; j < PSIRP_ID_LEN; j++) {
            if (idp->id[j] != 0) {
                break;
            }
        }
        if (j >= PSIRP_ID_LEN) {
            continue;
        }
        
        if (i > i_p+1) {
            printf(".. "
                   "00000000" "00000000" "00000000" "00000000"
                   "00000000" "00000000" "00000000" "00000000"
                   "\n");
        }
        
        printf("%03d  ", i); i_p = i;
        for (j = 0; j < PSIRP_ID_LEN; j++) {
            printf("%02x", idp->id[j]);
        }
        printf("\n");
    }
}

void ps_debug_print_meta(const char *str, void *meta) {

#define DUMMY_PRINT(x) do {      \
    for(i=0;i<PSIRP_ID_LEN;i++) \
	printf("%02x", x.id[i]); \
} while(0)

    int i, k;
    ps_meta_t pm = (ps_meta_t)meta;

    if (NULL != str) {
        printf("%s:\n", str);
    }

    printf("META DATA: %p\n", pm);
    if (NULL == pm) {
        return;
    }
    
    printf("         ID: ");
    DUMMY_PRINT(pm->pm_id);
    printf("\n");
    printf("       TYPE: "); 
    switch(pm->pm_type) {
    case PS_PUB_UNINITIALISED:
	printf("UNINITIALISED\n");
	break;
    case PS_PUB_UNKNOWN:
	printf("UNKNOWN\n");
	break;
    case PS_PUB_SCOPE:
	printf("SCOPE\n");
	break;
    case PS_PUB_DATA:
	printf("DATA\n");
	break;
    case PS_PUB_VERSION:
	printf("VERSION\n");
	break;
    case PS_PUB_PAGE:
	printf("PAGE\n");
	break;
    default:
	printf("ERROR (TYPE: %d)\n", pm->pm_type);
	break;
    }
    printf("       SIZE: %lu\n", pm->pm_size);

    printf("   VERSIONS: %d\n", pm->pm_vers_count);
    for(k=0;k<pm->pm_vers_count && k<PS_META_SUB_OBJECT_COUNT; k++) {
	printf("   VERS #%02d: ",k);
	DUMMY_PRINT(pm->pm_sub_object[k]);
	printf("\n");
    }

#undef DUMMY_PRINT
}
