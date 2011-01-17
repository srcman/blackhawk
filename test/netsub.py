#!/usr/local/bin/python2.6

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

from psirp.libpsirp import *
import time

SIDSTR, RIDSTR = "ab::", "ab::01"

pub = sub_sync_s(SIDSTR, RIDSTR)
print(pub.vridstr)
