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


#define PS_META_MAGIC  ps_meta_magic
#define PS_META_MAGIC_INIT \
    { 'M', 'e', 't', 'a', 'd', 'a', 't', 'a', ' ', 'r', 'u', 'l', 'e', 's' }

#define PS_VERS_MAGIC  ps_vers_magic
#define PS_VERS_MAGIC_INIT \
    { 'M', 'e', 't', 'a', 'v', 'e', 'r', 's', 'i', 'o', 'n', ' ', 'r', 'u', 'l', 'e', 's' }

#define PS_SDP_MAGIC   ps_sdp_magic
#define PS_SDP_MAGIC_INIT  \
    { 'S', 'c', 'o', 'p', 'e', ' ', 'm', 'a', 'g', 'i', 'c', ' ', 'r', 'u', 'l', 'e', 's' }

#define PS_PEP_MAGIC   ps_pep_magic
#define PS_PEP_MAGIC_INIT  \
    { 'P', 'u', 'b', 'l', 'i', 's', 'h', ' ', 'e', 'v', 'e', 'n', 't', ' ', 'p', 'a', 'g', 'e' }

#define PS_MAGIC_TEST(a, b) (!memcmp((a).id, (b).id, sizeof(psirp_id_t)))

extern psirp_id_t ps_meta_magic, ps_vers_magic, ps_sdp_magic;
