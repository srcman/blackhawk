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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <syslog.h> 
#include <stdarg.h>
#include <string.h> 
#include <stdio.h>
//#include <inttypes.h>
#include <sys/socket.h>
#include <errno.h>
//#include <sys/types.h>
//#include <sys/time.h>
//#include <sys/queue.h>
//#include <openssl/sha.h>
//#include <time.h>
#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif /* HAVE_LIBPCAP */
//#include <net/if.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <sys/param.h>

#define _LIBPSIRP

//#include <ps.h>
#include <libpsirp.h>
#include "psirp_debug.h"

#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (1)
#endif

#define MAX_DEBUG_STRLEN 4096
#define DEBUG_LEN_REMAINING \
     MAX_DEBUG_STRLEN - strlen(str) - 2 /* leave room for \n\0 */
/*
 * Debug print
 */
static char debug_mods[MAX_DEBUG_STRLEN] = "\0";
#ifdef MEM_DEBUG
static int debug_level = PSIRP_DBG_MOST | PSIRP_DBG_MEMORY;
#else
static int debug_level = PSIRP_DBG_ERR;
#endif
static int print_to_syslog = FALSE;
static int colors = FALSE;
#ifdef HAVE_LIBPCAP
static pcap_dumper_t *dumpfd = NULL;
#endif /* HAVE_LIBPCAP */


void
psirp_debug_init_print(int level, int log) {
    debug_level = level;
    print_to_syslog = log;
    psirp_debug_mem_init();
}
void
psirp_debug_init_module(char *module) {
    strcat(debug_mods, module);
}

int
psirp_debug_init_dump(char *filename) {
#ifdef HAVE_LIBPCAP
    pcap_t *pcap;

    pcap = pcap_open_dead(DLT_RAW, 2048);
    PSIRP_ET(NULL == pcap, PSIRP_FAIL, "Internal error: Cannot create pcap");
    dumpfd = pcap_dump_open(pcap, filename);
    PSIRP_ET(NULL == dumpfd, PSIRP_FAIL, "Cannot open dump file %s", filename);
    return 0;
#endif /* HAVE_LIBPCAP */

    return 0;
}

void
psirp_debug_cleanup(void) {
#ifdef HAVE_LIBPCAP
    if (NULL != dumpfd) {
        pcap_dump_close(dumpfd);
    }
#endif /* HAVE_LIBPCAP */
}

void
psirp_debug_print2log(void){
    print_to_syslog = TRUE;
}

void
psirp_debug_print2tty(void){
    print_to_syslog = FALSE;
}

void
psirp_debug_printcols(void) {
    colors = TRUE;
}

int
psirp_debug_get_level() {
    return debug_level;
}

void
psirp_debug_set_level(int level){
    debug_level = level;
}

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__linux__)
void
psirp_debug_print(int level, const char *file, 
                 const char *func, char *msg, ...) {
#else
void
psirp_debug_print(int level, const char *file, char *msg, ...) {
#endif
    va_list ap;
    char str[MAX_DEBUG_STRLEN]; /* max size of debug message */
    int priority = LOG_DEBUG;

    if ((debug_level & level) != level) {
        return;
    }
    if (strlen(debug_mods) > 0 && 
        ((*debug_mods != '!'  && strstr(debug_mods, file) == NULL) ||
         (*debug_mods == '!'  && strstr(debug_mods, file) != NULL)))
        return;

    switch(level & debug_level){
    case PSIRP_DBG_ERR:
	if (print_to_syslog == FALSE && colors == TRUE)
	    printf("%c[31m", 0x1B);
        priority = LOG_ERR;
        strcpy(str, "Error:   ");
        break;
    case PSIRP_DBG_WARN:
	if (print_to_syslog == FALSE && colors == TRUE)
	    printf("%c[35m", 0x1B);
        priority = LOG_WARNING;
        strcpy(str, "Warning: ");
        break;
    case PSIRP_DBG_INFO:
	if (print_to_syslog == FALSE && colors == TRUE)
	    printf("%c[36m", 0x1B);
        priority = LOG_INFO;
        strcpy(str, "Info:    ");
        break;
    case PSIRP_DBG_FNCE:
	if (print_to_syslog == FALSE && colors == TRUE)
	    printf("%c[32m", 0x1B);
        priority = LOG_DEBUG;
        strcpy(str, "Trace:   ");
        break;
    case PSIRP_DBG_TIMER:
        priority = LOG_DEBUG;
        strcpy(str, "Timer:   ");
        break;
    case PSIRP_DBG_HEXDUMP:
        priority = LOG_DEBUG;
        strcpy(str, "Hex:     ");
        break;
    case PSIRP_DBG_GARB:
        priority = LOG_DEBUG;
        strcpy(str, "Garbage: ");
        break;
    default:
        strcpy(str, "??:      "); 
        break;
    }

#if defined(__linux__)
    /* inserts timestamp [HH:MM:SS] to log entries */
    {
        struct tm *tmbuf;
        time_t curr_time;

        time(&curr_time);
        tmbuf = localtime(&curr_time);
        strftime(str + strlen(str), DEBUG_LEN_REMAINING, "[%H:%M:%S] ", tmbuf);
    }    
#endif

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__linux__)
    strcat(str, "[");
    strcat(str, func);
    strcat(str, "]: ");
#endif

    if (msg && strlen(msg) > DEBUG_LEN_REMAINING){
        strcat(str, "TOO LARGE MESSAGE\n");
    } else if(msg) {
        strcat(str, msg);
    }

    va_start(ap, msg);
    if (FALSE == print_to_syslog) {
        vprintf(str, ap);
	if (colors == TRUE) {
	    printf("%c[0m", 0x1B);
	}
        if (str[strlen(str)-1] != '\n') {
            putchar('\n');
        }
#if 0
        if (PSIRP_DBG_ERR == level) {
            perror("Errno  ");
	    errno = 0;
        }
#endif
    } else {
        vsyslog(priority, str, ap);
    }
    va_end(ap);
}


int
psirp_debug_hexdump(const char *file, unsigned char *buf, int len) {
    int i;

    if ((debug_level & PSIRP_DBG_HEXDUMP) != PSIRP_DBG_HEXDUMP) {
        return 0;
    }

    if (strlen(debug_mods) > 0 && strstr(debug_mods, file) == NULL &&
        ((*debug_mods != '!'  && strstr(debug_mods, file) == NULL) ||
         (*debug_mods == '!'  && strstr(debug_mods, file) != NULL)))
        return 0;

    printf("Hex:     ");
    printf(" ");
    for(i=0; i < len; i++) {
        if((i % 16) == 0 && i > 0)
            printf("\n         ");
        if((i % 4) == 0 && i > 0)
            printf(" ");
        printf("%02x", buf[i]);
    }
    printf("\n");

    return i;
}



void
psirp_debug_packetdump(char *buf, int len) {
#ifdef HAVE_LIBPCAP 
    struct pcap_pkthdr hdr;

    if (NULL == dumpfd) {
        return;
    }

    gettimeofday(&hdr.ts, NULL);
    hdr.caplen = len;
    hdr.len = len;
    pcap_dump((u_char *)dumpfd, &hdr, (u_char*)buf);
#endif /* HAVE_LIBPCAP */
}

#define MEMTABLE_SIZE 20000
static struct memtable {
    char file[50];
    uint32_t line;
    caddr_t addr;
    size_t bytes;
} m[MEMTABLE_SIZE];

int memtable_full  = 0;
int memtable_notin = 0;
int memtable_hit   = 0;
int memtable_miss  = 0;
int memtable_alloc = 0;

void
psirp_debug_mem_store(const char *file, uint32_t line, 
                     caddr_t addr, size_t bytes) {

    int i;
    int idx;

    if ((debug_level & PSIRP_DBG_MEMORY) != PSIRP_DBG_MEMORY) {
        return;
    }
    memtable_alloc++;
    
    idx = (uint32_t)((long int)addr % MEMTABLE_SIZE);
    if (m[idx].addr != 0) {
        for (i = idx < (MEMTABLE_SIZE - 1) ? idx + 1 : 0;
             m[i].addr != 0 && i != idx; 
             i = i < (MEMTABLE_SIZE - 1) ? i + 1 : 0);

        if (i == idx) {
            psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__,
                             __FUNCTION__,
                             "Memtable full (mem debugging not working)");
            memtable_full++;
            return;
        }
        idx = i;
        memtable_miss++;
    } else {
        memtable_hit++;
    }

    (void)strncpy(m[idx].file, file, sizeof(m[idx].file));
    m[idx].file[sizeof(m[idx].file) - 1] = '\0';
    m[idx].line = line;
    m[idx].addr = addr;
    m[idx].bytes = bytes;    

}

void
psirp_debug_mem_free(const char *file, uint32_t line, caddr_t addr) {

    int i;
    int idx;

    if ((debug_level & PSIRP_DBG_MEMORY) != PSIRP_DBG_MEMORY) {
        return;
    }
    
    idx = (uint32_t)((long int)addr % MEMTABLE_SIZE);
    if (m[idx].addr != addr) {
        for (i = idx < (MEMTABLE_SIZE - 1) ? idx + 1 : 0;
             m[i].addr != addr && i != idx; 
             i = i < (MEMTABLE_SIZE - 1) ? i + 1 : 0);

        if (i == idx) {
            psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__,
                             __FUNCTION__,
                             "Address(%p) not in memtable", addr);
            memtable_notin++;
            return;
        }
        idx = i;
        memtable_miss++;
    } else {
        memtable_hit++;
    }

    bzero(&m[idx], sizeof(m[0]));

}

void
psirp_debug_mem_init(void) {

    int i;

    if ((debug_level & PSIRP_DBG_MEMORY) != PSIRP_DBG_MEMORY) {
        return;
    }

    for (i = 0; i < MEMTABLE_SIZE; i++) {
        bzero(&m[i], sizeof(m[0]));
    }
}

void
psirp_debug_mem_print(void) {

    int i;

    if ((debug_level & PSIRP_DBG_MEMORY) != PSIRP_DBG_MEMORY) {
        return;
    }
    
    psirp_debug_print(PSIRP_DBG_GARB, __FILE_SHORT__, __FUNCTION__,
                     "************* MEM table stats *************");

    for (i = 0; i < MEMTABLE_SIZE; i++) {
        if (m[i].addr != 0) {
            psirp_debug_print(PSIRP_DBG_GARB, __FILE_SHORT__, __FUNCTION__,
                             "\n    %s:%d reserved %d bytes @%p", 
                             m[i].file, m[i].line, m[i].bytes, m[i].addr);
        }
    }

    psirp_debug_print(PSIRP_DBG_GARB, __FILE_SHORT__, __FUNCTION__,
                     "Memtable full: %d times ", memtable_full);
    psirp_debug_print(PSIRP_DBG_GARB, __FILE_SHORT__, __FUNCTION__,
                     "Not in Memtable: %d times ", memtable_notin);
    psirp_debug_print(PSIRP_DBG_GARB, __FILE_SHORT__, __FUNCTION__,
                     "Memtable hits: %d times ", memtable_hit);
    psirp_debug_print(PSIRP_DBG_GARB, __FILE_SHORT__, __FUNCTION__,
                     "Memtable misses: %d times ", memtable_miss);
    psirp_debug_print(PSIRP_DBG_GARB, __FILE_SHORT__, __FUNCTION__,
                     "Memtable allocs: %d times ", memtable_alloc);

    psirp_debug_print(PSIRP_DBG_GARB, __FILE_SHORT__, __FUNCTION__,
                     "************* MEM table stats *************");
}

void
psirp_debug_show_signals(int threaded)
{
    sigset_t set;
    char blocked[255];
    char unblocked[255];
    int i;

    sigemptyset(&set);

    if (threaded) {
        if (pthread_sigmask(0, NULL, &set)) {
            psirp_debug_print(PSIRP_DBG_ERR, __FILE_SHORT__, __FUNCTION__,
                              "Could not query thread's signal status: %d", 
                              errno);
        }
    } else {
        if (sigprocmask(0, NULL, &set)) {
             psirp_debug_print(PSIRP_DBG_ERR, __FILE_SHORT__, __FUNCTION__,
                              "Could not query signal status: %d", 
                              errno);
        }
    }

    memset(&blocked, 0, 255);
    memset(&unblocked, 0, 255);

    strcpy(blocked, "  Blocked signals: ");
    strcpy(unblocked, "Unblocked signals: ");

    for(i=1;i<SIGUSR2;i++) {
        if (sigismember(&set, i)) {
            snprintf(blocked, 255, "%s %d", blocked, i);
        } else {
            snprintf(unblocked, 255, "%s %d", unblocked, i);
        }
    }
        
    psirp_debug_print(PSIRP_DBG_GARB, __FILE_SHORT__, __FUNCTION__,
                      "Signal sets:\n%s\n%s", blocked, unblocked);
}

void psirp_debug_meta(psirp_pub_t pub)
{

#define DUMMY_PRINT(x) do {      \
    for(i=0;i<PSIRP_ID_LEN;i++) \
	printf("%02x", x.id[i]); \
} while(0)

    int i, k;
    ps_meta_t pm = pub->pub_meta;
    int sub_object_count = 0;

    printf("Contents of publication descriptor: %p\n", pub);
    printf("META DATA: %p\n", pm);
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

    switch (pm->pm_type) {
    case PS_PUB_VERSION:
        sub_object_count = pm->pm_page_count;
        printf("      PAGES: %d\n", sub_object_count);
        break;
    default:
        sub_object_count = pm->pm_vers_count;
        printf("   VERSIONS: %d\n", sub_object_count);
        break;
    }
    for(k = 0; k < sub_object_count && k < PS_META_SUB_OBJECT_COUNT; k++) {
        switch (pm->pm_type) {
        case PS_PUB_VERSION:
            printf("   PAGE #%02d: ", k);
            break;
        default:
            printf("   VERS #%02d: ", k);
            break;
        }
	DUMMY_PRINT(pm->pm_sub_object[k]);
	printf("\n");
    }
    printf("     MD LEN: %lu\n", pub->pub_mlen);
    printf("--------------------------------------------\n");
    printf("DATA: %p\n", pub->pub_data);
    printf("     LENGTH: %lu\n", pub->pub_dlen);
    printf("--------------------------------------------\n");

#undef DUMMY_PRINT
}

void psirp_debug_meta2(psirp_pub_t pub)
{
    uint8_t *ptr;
    int i;

    ptr = (uint8_t *)PSFS_PUB_META(pub);

    for(i=1;i<=1024;i++) {
        printf("%02x%s", ptr[i-1], i%32 ? " " : "\n");
    }

}

char *psirp_debug_idstoa(psirp_id_t *sid,  psirp_id_t *rid,
                         psirp_id_t *vrid, psirp_id_t *fid)
{
    static char idstr[(4 * PSIRP_ID_LEN*2) + 4];
    char *sti;
    char *str;
    psirp_id_t *ids[4] = {sid, rid, vrid, fid};
    int i;
    
    if (PSIRP_DBG_NONE == debug_level) {
        idstr[0] = '\0';
        return idstr;
    }
    
    bzero(idstr, sizeof(idstr));
    sti = &idstr[0];
    
    for (i = 0; i < 4; i++) {
        psirp_id_t *id = ids[i];
        
        if (NULL != id) {
            str = (char *)psirp_idtoa(ids[i]);
            sti = stpcpy(sti, str); /* XXX */
        }
        
        if (i < 3) {
            *sti = '/';
            sti++;
        }
    }
    
    return idstr;
}
