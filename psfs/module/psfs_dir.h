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

int psfs_dir_cntdents(struct psfs_node *node, off_t *cntp);
int psfs_dir_getdents(struct psfs_node *node, struct uio *uio, u_long *cookies, off_t cntp, int *eofflag);
