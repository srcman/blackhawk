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

#ifndef _PSIRP_COMMON_TYPES_H
#define _PSIRP_COMMON_TYPES_H

//#include <sys/queue.h>

//#include <libpsirp.h>

/* configuration options (should be in a file!) */

#define MAX_PUBS 10       /**< Maximum number of active publications. */

#define PUBSUB_MNT   "/pubsub"         /* mount point */

/* RID policy types */
#define PSIRP_RZV_RID_RANDOM          0x01
#define PSIRP_RZV_RID_PLA             0x02

#define PSIRP_VIRTUAL_IFACE            "virtual0"

#define PSIRP_MAX_NO_IFACES            10
#define PSIRP_ETHERNET_TYPE            0xacdc
#define PSIRP_MAX_HEADER_LEN           1024
#define PSIRP_MAX_PACKET_LEN           ETHER_MAX_LEN_JUMBO
#define PSIRP_OUTQ_BATCH_SIZE          32 /* packets */
#define PSIRP_OUTQ_TIMEOUT_SEC         0
#define PSIRP_OUTQ_TIMEOUT_NSEC        50000000 /* 1 ms = 1 000 000 ns */

#define PSIRP_CHUNK_SIZE               1024   /* bytes */
#define PSIRP_MAX_PUB_SIZE             512000L
#define PSIRP_MAX_FID_ONES             (PSIRP_ID_LEN*8)/2 /* XXX */

#define PSIRP_FALSE                    0x0
#define PSIRP_TRUE                     0x1

/* Success codes */
#define PSIRP_OK                       0x000000

/* Error codes */
#define PSIRP_FAIL                     0xff0000
#define PSIRP_FAIL_DEVRANDOM           0xff0010
//#define PSIRP_FAIL_PCAP_DEV            0xff0011
//#define PSIRP_FAIL_PCAP_FILTER         0xff0012
#define PSIRP_FAIL_SELECT              0xff0013
//#define PSIRP_FAIL_PCAP_CAPTURE        0xff0014
#define PSIRP_FAIL_ETH_TYPE            0xff0015
#define PSIRP_FAIL_KLDLOAD             0xff0016
#define PSIRP_FAIL_MODFIND             0xff0017
#define PSIRP_FAIL_MODSTAT             0xff0018
#define PSIRP_FAIL_SYSCALL             0xff0019
#define PSIRP_FAIL_ADDRNULL            0xff0020
#define PSIRP_FAIL_MALLOC              0xff0021
#define PSIRP_FAIL_NOTFOUND            0xff0022
#define PSIRP_FAIL_INVALIDARG          0xff0023
//#define PSIRP_FAIL_LIBNET_INIT         0xff0024
//#define PSIRP_FAIL_LIBNET_BUILD_ETH    0xff0025
//#define PSIRP_FAIL_LIBNET_WRITE        0xff0026
//#define PSIRP_FAIL_PCAP_UNEXPECTED_PCK 0xff0027
#define PSIRP_FAIL_UNKNOWN_FD          0xff0028
#define PSIRP_FAIL_DROP_PACKET         0xff0029
#define PSIRP_FAIL_PLA_HEADER_MISSING  0xff0030
#define PSIRP_FAIL_CANNOT_CREATE_HDR   0xff0031
#define PSIRP_FAIL_HEADER_LEN          0xff0032
#define PSIRP_FAIL_UNKNOWN_RID         0xff0033
#define PSIRP_FAIL_OUT_OF_BUFFER       0xff0034
#define PSIRP_FAIL_FWD_NO_IFACES_OUT   0xff0035
#define PSIRP_FAIL_RZV_TYPE            0xff0036
//#define PSIRP_FAIL_BMAP                0xff0037
#define PSIRP_FAIL_OUT_OF_RANGE        0xff0038
#define PSIRP_FAIL_DOUBLE_INIT         0xff0039
#define PSIRP_FAIL_TEST_END            0xff0040
#define PSIRP_FAIL_UNKNOWN_HDR         0xff0041
#define PSIRP_FAIL_NULL_POINTER        0xff0042
#define PSIRP_FAIL_BUF_LEN             0xff0043
#define PSIRP_FAIL_ALREADY_EXISTS      0xff0044
#define PSIRP_FAIL_CANNOT_ADD          0xff0045
#define PSIRP_FAIL_HANDLER_NULL        0xff0046
#define PSIRP_FAIL_UNKNOWN_RID_POLICY  0xff0047
#define PSIRP_FAIL_FILEREADERROR       0xff0048

/* Define own data types */
typedef unsigned long int psirp_error_t;

#endif /* _PSIRP_COMMON_TYPES_H */
