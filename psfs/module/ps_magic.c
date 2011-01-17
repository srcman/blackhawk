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

#include "ps.h" 
#include "ps_magic.h"

psirp_id_t ps_meta_magic = { PS_META_MAGIC_INIT };

psirp_id_t ps_sdp_magic  = { PS_SDP_MAGIC_INIT };
