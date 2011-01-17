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

SID_S = "::aa00"
RID_S = "::aa01"

def _main():
    pub = sub_sync_s(SID_S, RID_S, None)
    print(pub.buffer[:])

if __name__ == "__main__":
    _main()
