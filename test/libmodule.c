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

/*
 * Helper object to provide direct access to the system calls.
 * Linked (as an object) to the testers in this directory.
 */

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/event.h>
#include <sys/time.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sysexits.h>

#define _LIBPSIRP

#include <ps.h>
#include <ps_syscall.h>

static struct module_stat mstat;
static int syscall_num;

struct ps_args {
    struct psfs_pub *pub;
    psirp_id_t sid;
    psirp_id_t rid;
};


int
prepare() 
{
    mstat.version = sizeof(mstat);
    if (modstat(modfind(PS_SYSCALL_MODULE_NAME), &mstat) == -1) {
        perror("modstat/modfind");
        return -1;
    }

    syscall_num = mstat.data.intval;

    return 0;
}

static int call(int op, struct ps_args *args) 
{
    struct ps_syscall_sc_arg sa;
    struct ps_syscall_arg arg;
    struct psfs_pub *pub;
    int retval = 0;

    pub = args->pub;

    memset(&arg, 0, sizeof(arg));

    arg.a_op     = op;

    arg.a_retval = pub->pub_fd;
    arg.a_sid    = args->sid;
    arg.a_rid    = args->rid;
    arg.a_meta   = (caddr_t)pub->pub_meta;
    arg.a_mlen   = pub->pub_mlen;
    arg.a_data   = pub->pub_data;
    arg.a_dlen   = pub->pub_dlen;

    sa.p = &arg;

    if ((retval = syscall(syscall_num, sa))) {
	if (retval < 0 && 0 == errno) {
	    printf("ERROR: retval == %d && errno == %d\n", retval, errno);
	    exit (EX_OSERR);
	}
        return retval;
    }

    pub->pub_fd   = arg.a_retval;
    pub->pub_sid  = arg.a_sid;
    pub->pub_meta = (ps_meta_t)arg.a_meta;
    pub->pub_mlen = arg.a_mlen;
    pub->pub_data = arg.a_data;
    pub->pub_dlen = arg.a_dlen;

    return 0;

}

int
create(struct psfs_pub *pub)
{
    struct ps_args args = {
        pub, {{0}}, {{0}}
    };

    return call(PS_SYSCALL_CRE, &args);
}

int
publish(psirp_id_t sid, psirp_id_t rid, struct psfs_pub *pub)
{
    struct ps_args args = {
        pub, sid, rid 
    };

    return call(PS_SYSCALL_PUB, &args);
}

int
subscribe(psirp_id_t sid, psirp_id_t rid, struct psfs_pub *pub)
{
    struct ps_args args = {
        pub, sid, rid
    };

    return call(PS_SYSCALL_SUB, &args);
}
