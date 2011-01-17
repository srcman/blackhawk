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

typedef unsigned long  u_int64_t;
typedef unsigned int   u_int32_t;
typedef unsigned short u_int16_t;
typedef unsigned char  u_int8_t;

typedef long  int64_t;
typedef int   int32_t;
typedef short int16_t;
typedef char  int8_t;

typedef void * psirp_pub_t;
typedef void * caddr_t;


%typemap(in) psirp_id_t * {
    if (PyBuffer_Check($input)) {
	void *buf = NULL;
	long len = 0;
	
	//PSIRP_DEBUG(PSIRP_DBG_GARB, "Buffer -> psirp_id_t");
	
        PyObject_AsReadBuffer($input, (const void **)&buf, &len);
	$1 = (psirp_id_t *)buf;
    }
    else {
	//PSIRP_DEBUG(PSIRP_DBG_WARN, "String -> psirp_id_t");
#if 1
	/* Treats the given input as a string. */
	$1 = (psirp_id_t *)PyString_AsString($input);
#else
	/* Faster, but without error checking. */
	$1 = (psirp_id_t *)PyString_AS_STRING($input);
#endif
    }
}
%typemap(out) psirp_id_t * {
#if 1
    /* Returns a non-writable but hashable buffer. */
    PyObject *o = PyBuffer_FromMemory($1, sizeof(*$1));
#elif 0
    /* Returns a writable but non-hashable buffer. */
    PyObject *o = PyBuffer_FromReadWriteMemory($1, sizeof(*$1));
#else
    /* Returns a string, but copies data. */
    PyObject *o = SWIG_FromCharPtrAndSize((char*)$1, sizeof(*$1));
#endif
    $result = SWIG_Python_AppendOutput($result, o);
}
/* %typemap(argout) psirp_id_t * { */
/*     /\* XXX *\/ */
/* } */

%typemap(in, numinputs=0) psirp_pub_t * {
    $1 = ($1_ltype)malloc(sizeof($*1_ltype));
    memset($1, 0, sizeof($*1_ltype));
}
%typemap(argout) psirp_pub_t * {
    PyObject *o = SWIG_NewPointerObj(SWIG_as_voidptr(*$1),
                                     $descriptor(psirp_pub_t), /* ? */
                                     0);
    $result = SWIG_Python_AppendOutput($result, o);
}
%typemap(freearg) psirp_pub_t * {
    if ($1) {
        free($1);
        $1 = NULL;
    }
}


//%typemap(out) u_int8_t [ANY] { /* u_int8_t[] -> read-write buffer */
//    PyObject *o = PyBuffer_FromReadWriteMemory($1, $1_dim0);
//    $result = SWIG_Python_AppendOutput($result, o);
//}
