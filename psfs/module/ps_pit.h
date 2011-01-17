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
 * Beginnings for an efficient implementation for looking up
 * data based on the *rid* only.
 *
 * The data is organized as page-sized objects.
 * Each page consists of a header and 61 pits of 64 bytes.  (Note that 61 is a prime).
 * If you had a differently sized page, you wanted to change these.
 */

int ps_pit_init(void);
void ps_pit_cleanup(void);
int ps_pit_get(psirp_id_t id, ps_pubi_t *pubip);
int ps_pit_getn(struct thread *td, psirp_id_t id, ps_pubi_t *pubip); /* Get & create if doesn't exist */

int ps_pit_status(char *buf, int maxlen);
