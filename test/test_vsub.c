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


#include <sys/param.h>
#include <libpsirp.h>

#include <string.h>

#include <stdio.h>

int main(void) {
    psirp_pub_t pub;
    void *pub_data;
    psirp_id_t sid, rid;
    const char sid_str[] = "12::34";
    const char rid_str[] = "56::78";
    const char data_str[] = "Hello, world!\n";
    
    /* XXX: Error checks missing! */
    
    /* Create and publish */

    psirp_create(20, &pub);
    pub_data = psirp_pub_data(pub);
    memcpy(pub_data, data_str, sizeof(data_str));
    
    psirp_atoid(&sid, sid_str);
    psirp_atoid(&rid, rid_str);
    
    psirp_publish(&sid, &rid, pub);

    psirp_free(pub);

    /* Subscribe to scope */

    psirp_subscribe(&sid, &sid, &pub);
    {
        psirp_id_t *rids;
        int rid_count;
        int i;
        
        psirp_scope_get_rids(pub, &rids, &rid_count);
        for (i = 0; i < rid_count; i++) {
            printf("RId %02d: %s\n", i, psirp_idtoa(&rids[i]));
        }
    }
    psirp_free(pub);

    /* Subscribe to data */

    psirp_subscribe(&sid, &rid, &pub);
    {
        psirp_id_t *rids;
        int rid_count;
        int i;
        
        psirp_pub_get_vrids(pub, &rids, &rid_count);
        for (i = 0; i < rid_count; i++) {
            printf("vRId %02d: %s\n", i, psirp_idtoa(&rids[i]));
        }
    }
    //psirp_free(pub);

    /* Subscribe to version */

    {
        psirp_pub_t pub1;
        
        psirp_subscribe(&rid, psirp_pub_current_version(pub), &pub1);
        {
            psirp_id_t *rids;
            int rid_count;
            int i;
        
            psirp_version_get_prids(pub1, &rids, &rid_count);
            for (i = 0; i < rid_count; i++) {
                printf("pRId %02d: %s\n", i, psirp_idtoa(&rids[i]));
            }
        }
        psirp_free(pub1);
    }
    
    psirp_free(pub);

    return 0;
}
