#!/usr/local/bin/python2.6

#
# Copyright (C) 2010, Oy L M Ericsson Ab, NomadicLab <pubsub@nomadiclab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# Alternatively, this software may be distributed under the terms of the BSD
# license.
#
# See LICENSE and COPYING for more details.
#


def _main():
    import sys, psirp.libpsirp
    
#     input = ""
#     for arg in sys.argv:
#         input += "%s " % arg
#     else:
#         input += "\n"
#     sys.stderr.write(input)
#     sys.stderr.flush()
    
    # First convert the hex string to a byte string, then back to a
    # hex string. Why would we want to do this? Well, if the input
    # string is 64 characters long and contains lots of zeros, the
    # output string will be much shorter as the longest sequence of
    # zeros has been replaced with ::.
    a1 = sys.argv[1]
    id = psirp.libpsirp.atoid(a1)
    a2 = psirp.libpsirp.idtoa(id)

#     sys.stderr.write("a2: %s\n" % a2)
    
    # Print the output string (hopefully without newline chars)
    sys.stdout.write(a2)
    sys.stdout.flush()

if __name__ == "__main__":
    _main()
