#
# Copyright (C) 2009-2010, Oy L M Ericsson Ab, NomadicLab.
# All rights reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version
# 2 as published by the Free Software Foundation.
#
# Alternatively, this software may be distributed under the terms of
# the BSD license.
#
# See LICENSE and COPYING for more details.
#

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(psirp, 0.3, psirp-code@hiit.fi)
AC_PREREQ(2.57)
AC_REVISION($Id$)
AC_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE
AC_PROG_LIBTOOL

# Debug compile
AC_ARG_ENABLE(debug,
[  --enable-debug	  Turn on debugging],
[case ${enableval} in
  yes) debug=true ;;
  no)  debug=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
esac],[debug=false])
AM_CONDITIONAL(debug, test x$debug = xtrue)

AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
#AM_PROG_CC_C_O
AM_PATH_PYTHON(2.6)

# Checks for library functions.
#AC_FUNC_FORK
#AC_FUNC_MALLOC
#AC_FUNC_SELECT_ARGTYPES
#AC_TYPE_SIGNAL
#AC_C_CONST
#AC_HEADER_STDBOOL

# check for GMP
#AC_CHECK_LIB(gmp, __gmpz_init, , [AC_MSG_ERROR([GNU MP not found, see http://swox.com/gmp/])])

AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(psfs/Makefile)
AC_CONFIG_FILES(psfs/scoped/Makefile)
AC_CONFIG_FILES(libpsirp/Makefile)
AC_CONFIG_FILES(libpsirp/src/Makefile)
AC_CONFIG_FILES(libpsirp/test/Makefile)
AC_CONFIG_FILES(libpsirp/python/Makefile)
AC_CONFIG_FILES(libpsirp/ruby/Makefile)
AC_CONFIG_FILES(utils/Makefile)
AC_CONFIG_FILES(helpers/Makefile)
AC_CONFIG_FILES(helpers/netiod/Makefile)
AC_CONFIG_FILES(helpers/laird/Makefile)
AC_CONFIG_FILES(helpers/subevd/Makefile)
AC_CONFIG_FILES(test/Makefile)
#AC_SUBST(YFLAGS)
AC_OUTPUT
