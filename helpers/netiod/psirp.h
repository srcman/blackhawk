/*
* Copyright (C) 2009, Oy L M Ericsson Ab, NomadicLab <pubsub@nomadiclab.com>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation.
*
* Alternatively, this software may be distributed under the terms of the BSD
* license.
*
* See LICENSE and COPYING for more details.
*/

#ifndef _PSIRP_H_
#define _PSIRP_H_

psirp_error_t psirp_fatal(int);

#define PSIRP_EF(func) \
{ psirp_error_t e = (func); \
  if (PSIRP_OK != e) { \
    psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__, __FUNCTION__, "Error"); \
    RETURN e; \
  } \
}

#define PSIRP_EFL(func, level) \
{ psirp_error_t e = (func); \
  if (PSIRP_OK != e) { \
    psirp_debug_print((level), __FILE_SHORT__, __FUNCTION__, "Error"); \
    RETURN e; \
  } \
}

#define PSIRP_EFLM(func, level, args...) \
{ psirp_error_t e = (func); \
  if (PSIRP_OK != e) { \
    psirp_debug_print((level), __FILE_SHORT__, __FUNCTION__, args); \
    RETURN e; \
  } \
}

#define PSIRP_EFB(func, block) \
{ psirp_error_t e = (func); \
  if (PSIRP_OK != e) { \
    block; \
    psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__, __FUNCTION__, "Error"); \
    RETURN e; \
  } \
}

#define PSIRP_ET(test, err, args...) \
{ psirp_error_t e = (err); \
  if ((test)) { \
    psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__, __FUNCTION__, args); \
    RETURN e; \
  } \
}

#define PSIRP_ETL(test, err, level, args...) \
{ psirp_error_t e = (err); \
  if ((test)) { \
    psirp_debug_print((level), __FILE_SHORT__, __FUNCTION__, args); \
    RETURN e; \
  } \
}

#define PSIRP_ETB(test, err, block, args...) \
{ psirp_error_t e = (err); \
  if ((test)) { \
    block; \
    psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__, __FUNCTION__, args); \
    RETURN e; \
  } \
}

#define PSIRP_ETBL(test, err, level, block, args...) \
{ psirp_error_t e = (err); \
  if ((test)) { \
    block; \
    psirp_debug_print(level, __FILE_SHORT__, __FUNCTION__, args); \
    RETURN e; \
  } \
}

#define PSIRP_ETLB(test, err, level, block, args...) \
{ psirp_error_t e = (err); \
  if ((test)) { \
    psirp_debug_print(level, __FILE_SHORT__, __FUNCTION__, args); \
    block; \
    RETURN e; \
  } \
}

/**
 * Checks if we have an error condition, and if so, returns an error code
 * and outputs debug prints.
 * @param err The errorcode. If err != PSIRP_OK, we have an error
 * @param args Normal printf arguments for debug print
 */
#define PSIRP_EC(err, args...) \
{ psirp_error_t e = (err); \
  if (PSIRP_OK != e) { \
    psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__, __FUNCTION__, args); \
    RETURN e; \
  } \
}

#define PSIRP_ECL(err, level, args...) \
{ psirp_error_t e = (err); \
  if (PSIRP_OK != e) { \
    psirp_debug_print((level), __FILE_SHORT__, __FUNCTION__, args); \
    RETURN e; \
  } \
}

#define PSIRP_ECB(err, block, args...) \
{ psirp_error_t e = (err); \
  if (PSIRP_OK != e) { \
    psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__, __FUNCTION__, args); \
    block; \
    RETURN e; \
  } \
}

#define PSIRP_ECBL(err, block, level, args...) \
{ psirp_error_t e = (err); \
  if (PSIRP_OK != e) { \
    psirp_debug_print((level), __FILE_SHORT__, __FUNCTION__, args); \
    block; \
    RETURN e; \
  } \
}

/** 
 * Allocates memory. If fails, barks and calls abort (use with care).
 * @param addr The address where the memory is allocated. Note: you should
 *             not use expressions here.
 * @param size Nrof bytes to allocate
 */
#define PSIRP_MALLOC(addr, size)                                         \
    {   (addr) = (void*)malloc((size));                                 \
        if ((addr) == NULL) {                                           \
            psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__,              \
                             __FUNCTION__,                              \
                             "No memory available");                    \
            abort();                                                    \
        }                                                               \
        psirp_debug_mem_store(__FILE_SHORT__, __LINE__, (void*)(addr),   \
                             size);                                     \
    }

/** 
 * Allocates memory. If fails, fails with the given error code.
 * @param addr The address where the memory is allocated. 
 *        Note: you should not use expressions here.
 * @param size Nrof bytes to allocate
 * @param err The error code to use if allocation fails
 */
#define PSIRP_MALLOC_E(addr, size, err)                                  \
    {   (addr) = (void*)malloc((size));                                 \
        PSIRP_ET((addr) == NULL, err, "No memory available");            \
        psirp_debug_mem_store(__FILE_SHORT__, __LINE__, (void*)(addr),   \
                             size);                                     \
    }

/** 
 * Allocates memory. If fails, executes the given block of code.
 * @param addr The address where the memory is allocated. 
 *        Note: you should not use expressions here.
 * @param size Nrof bytes to allocate
 * @param block The block to execute if the allocation fails
 */
#define PSIRP_MALLOC_B(addr, size, block)                                \
    {   (addr) = (void*)malloc((size));                                 \
        if ((addr) == NULL) {                                           \
            psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__,              \
                             __FUNCTION__,                              \
                             "No memory available");                    \
            block;                                                      \
        }                                                               \
        psirp_debug_mem_store(__FILE_SHORT__, __LINE__, (void*)(addr),   \
                             size);                                     \
    }

/** 
 * Allocates memory. If fails, executes the given block of code and fails
 * with the given error code.
 * @param addr The address where the memory is allocated. 
 *        Note: you should not use expressions here.
 * @param size Nrof bytes to allocate
 * @param err The error code to use if allocation fails
 * @param block The block to execute if the allocation fails
 */
#define PSIRP_MALLOC_EB(addr, size, err, block)                          \
    {   (addr) = (void*)malloc((size));                                 \
        PSIRP_ETB((addr) == NULL, err, block, "No memory available");    \
        psirp_debug_mem_store(__FILE_SHORT__, __LINE__, (void*)(addr),   \
                             size);                                     \
    }

/**
 * Stores the given memory buffer reference for debug purposes.
 * @param addr The address to store
 * @param size Nrof bytes allocated to the address
 */
#define PSIRP_STORE_MEM(addr, size)                                      \
    {   if (NULL == (addr)) {                                           \
            psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__,              \
                             __FUNCTION__,                              \
                             "Trying to store NULL pointer");           \
        } else {                                                        \
            psirp_debug_mem_store(__FILE_SHORT__, __LINE__,              \
                                 (void*)(addr), size);                  \
        }                                                               \
    }

/**
 * Frees the given memory buffer reference (does not call free()) for
 * debug purposes @see PSIRP_STORE_MEM
 * @param addr The address of the buffer
 */
#define PSIRP_FREE_MEM(addr)                                             \
    {   if (NULL == (addr)) {                                           \
            psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__,              \
                             __FUNCTION__,                              \
                             "Trying to free NULL pointer");            \
        } else {                                                        \
            psirp_debug_mem_free(__FILE_SHORT__, __LINE__,               \
                                 (void*)(addr));                        \
        }                                                               \
    }



/**
 * Frees the given buffer
 * @param addr The address of the buffer
 */
#define PSIRP_FREE(addr)                                             \
    {   if ((addr) == NULL) {                                       \
            psirp_debug_print(PSIRP_DBG_WARN, __FILE_SHORT__,          \
                             __FUNCTION__,                          \
                             "Trying to free NULL pointer");        \
        } else {                                                    \
            free((addr));                                           \
            psirp_debug_mem_free(__FILE_SHORT__, __LINE__,           \
                                (void*)(addr));                     \
        }                                                           \
    }

#endif
