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

extern unsigned long ps_debug_mask;

#ifdef DEBUG
#define PS_PRINTF(context, format, ...)			     \
    do {                                                     \
       if (ps_debug_mask & (context))                        \
          printf("%s: " format, __func__ , ##__VA_ARGS__);   \
    } while (0)
#else
#define PS_PRINTF(format, ...)
#endif

#define PS_DEBUG_ERROR     0x00000001
#define PS_DEBUG_WARNING   0x00000002
#define PS_DEBUG_SYSCALL   0x00000010
#define PS_DEBUG_KNOTE     0x00000020
#define PS_DEBUG_EVENT     0x00000040 
#define PS_DEBUG_SCOPE     0x00000080
#define PS_DEBUG_PIT       0x00000100
#define PS_DEBUG_OBJ       0x00000200
#define PS_DEBUG_MAP       0x00000400
#define PS_DEBUG_NODE      0x00001000
#define PS_DEBUG_DIR       0x00002000
#define PS_DEBUG_VFS       0x00004000
#define PS_DEBUG_FILT      0x00008000
#define PS_DEBUG_SOCKET    0x00010000
#define PS_DEBUG_CRYPTO    0x00020000
#define PS_DEBUG_LOCK      0x00100000
#define PS_DEBUG_FUNTRACE  0x00200000

void ps_debug_dump_meta_hdr(const char *str, void *meta);
void ps_debug_print_meta_sub(const char *str, void *meta);

void ps_debug_print_meta(const char *str, void *meta);
