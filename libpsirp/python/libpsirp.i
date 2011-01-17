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

%module libpsirp_py
%{
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <vm/vm.h>

/* libpsirp */
#define _LIBPSIRP /* XXX */
#include "../include/libpsirp.h"
#include "../src/psirp_debug.h"

/* Scopes and pub/sub events */
#include "../../psfs/module/ps_scope.h"
#include "../../psfs/module/ps_event.h"
#include "../../psfs/module/ps_magic.h"

/* XXX: Network I/O and IPC */
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "../../helpers/netiod/psirp_common_types.h"
#include "../../helpers/netiod/psirpd_hdrs.h"
#include "../../helpers/netiod/psirpd_ipc.h"
%}

%include libpsirp_types.i
%include libpsirp_api.i

/* XXX: Scope R/W and event page access */
%include libpsirp_scopes.i

/* XXX: Network I/O and IPC */
%include libpsirp_net.i

