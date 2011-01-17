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

#ifndef _PSIRP_DEBUG_H_
#define _PSIRP_DEBUG_H_

#define __FUNCTION__ __func__

/*
 * DEBUG levels. Used with psirp_print() function
 */

#define PSIRP_DBG_NONE    0x0
#define PSIRP_DBG_ERR     0x1    /* for error messages */ 
#define PSIRP_DBG_WARN    0x2    /* for warning messages */
#define PSIRP_DBG_INFO    0x4    /* for info messages */
#define PSIRP_DBG_FNCE    0x8    /* for function entries and returns */
#define PSIRP_DBG_TIMER   0x10
#define PSIRP_DBG_HEXDUMP 0x40 
#define PSIRP_DBG_GARB    0x80   /* for other debugging purposes */
#define PSIRP_DBG_MEMORY  0x100
#define PSIRP_DBG_ALL     0xFFFF 
#define PSIRP_DBG_MOST    0x0007

/*
 * Debug printing
 */

#define __FILE_SHORT__                                          \
    (strrchr(__FILE__, '/')? strrchr(__FILE__, '/')+1 : __FILE__)

#ifdef DEBUG

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__linux__)
#define PSIRP_DEBUG(x, args...)                                  \
    psirp_debug_print((x), __FILE_SHORT__,  __FUNCTION__, args)

#define PSIRP_DEBUG_FUNC()                                \
    PSIRP_DEBUG((PSIRP_DBG_FNCE, __FUNCTION__, "%s(%d): ",  \
               __FILE_SHORT__, __LINE__))

#define PSIRP_DEBUG_HEXDUMP(bin, len, args...)                            \
    psirp_debug_print(PSIRP_DBG_HEXDUMP, __FILE_SHORT__,  __FUNCTION__, args); \
    psirp_debug_hexdump(__FILE_SHORT__, (unsigned char *)bin, len)

#define ENTER()                                                     \
    psirp_debug_print(PSIRP_DBG_FNCE, __FILE_SHORT__, __FUNCTION__,    \
                     "%s(%d): ENTER\n", __FILE_SHORT__, __LINE__) 

#define RETURN /* WARNING: two "lines", requires if (...) { ... } format */ \
    psirp_debug_print(PSIRP_DBG_FNCE, __FILE_SHORT__, __FUNCTION__,         \
                     "%s(%d): RETURN", __FILE_SHORT__, __LINE__);           \
    return
#if 0
#define RETURN(retval) \
    do {                                                                \
        psirp_debug_print(PSIRP_DBG_FNCE, __FILE_SHORT__, __FUNCTION__, \
                          "%s(%d): RETURN", __FILE_SHORT__, __LINE__);  \
        return (retval);                                                \
    } while (0);
#endif

#define PSIRP_DEBUG_MEM_STORE(file, line, addr, bytes) \
    psirp_debug_mem_store(file, line, addr, bytes);

#define PSIRP_DEBUG_MEM_FREE(file, line, addr) \
    psirp_debug_mem_free(file, line, addr);

#else
#define PSIRP_DEBUG(x, args...)                                       \
    psirp_debug_print((x), __FILE_SHORT__, __FUNCTION__ ": " args)

#define PSIRP_DEBUG_FUNC()                                    \
    PSIRP_DEBUG((PSIRP_DBG_FNCE, "%s(%d)/%s: ",                 \
               __FILE_SHORT__, __LINE__, __FUNCTION__));

#define ENTER()                                                         \
    psirp_debug_print(PSIRP_DBG_FNCE, __FILE_SHORT__, "%s(%d)/%s: ENTER\n", \
                     __FILE_SHORT__, __LINE__, __FUNCTION__)

#define RETURN /* WARNING: two "lines", requires if (...) { ... } format */  \
    psirp_debug_print(PSIRP_DBG_FNCE, __FILE_SHORT__, "%s(%d)/%s: RETURN\n", \
                     __FILE_SHORT__, __LINE__, __FUNCTION__);                \
    return

#define PSIRP_DEBUG_MEM_STORE(file, line, addr, bytes) \
    psirp_debug_mem_store(file, line, addr, bytes);

#define PSIRP_DEBUG_MEM_FREE(file, line, addr) \
    psirp_debug_mem_free(file, line, addr);

#endif /* FreeBSD */

#else
#define PSIRP_DEBUG(x, args...)
#define PSIRP_DEBUG_FUNC()
#define PSIRP_DEBUG_HEXDUMP(bin, len, args...)
#define ENTER()
#define RETURN return
#define PSIRP_DEBUG_MEM_STORE(file, line, addr, bytes)
#define PSIRP_DEBUG_MEM_FREE(file, line, addr)
#endif /* DEBUG*/

void psirp_debug_init_print(int level, int log);
void psirp_debug_init_module(char *module);
int psirp_debug_init_dump(char *filename);
void psirp_debug_cleanup(void);
void psirp_debug_print2log(void);
void psirp_debug_print2tty(void);
void psirp_debug_printcols(void);
int psirp_debug_get_level();
void psirp_debug_set_level(int level);

#ifdef SWIG
void psirp_debug_print(int, const char*, const char *, const char *);
#elif defined(__FreeBSD__) || defined(__APPLE__) || defined(__linux__)
void psirp_debug_print(int, const char *,const char *, char *, ...);
#else
void psirp_debug_print(int, const char *, char *, ...);
#endif

int psirp_debug_hexdump(const char *, unsigned char *, int);

void psirp_debug_packetdump(char *, int);

void psirp_debug_mem_store(const char*, uint32_t, caddr_t, size_t);
void psirp_debug_mem_free(const char*, uint32_t, caddr_t);
void psirp_debug_mem_init(void);
void psirp_debug_mem_print(void);

void psirp_debug_show_signals(int);
void psirp_debug_meta(psirp_pub_t pub);

char *psirp_debug_idstoa(psirp_id_t *sid,  psirp_id_t *rid,
                         psirp_id_t *vrid, psirp_id_t *fid);


#endif /* _PSIRP_DEBUG_H */
