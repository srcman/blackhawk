#!/usr/bin/env python


import sys


C_TYPE = '*' # C files (e.g. .c, .h, .i)
S_TYPE = '#' # Script files (e.g. .py, .sh)

C_COPYRIGHT_OLD = \
"""/*
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
*/"""

C_COPYRIGHT_NEW = \
"""/*
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
 */"""

S_COPYRIGHT_OLD = \
"""#
# Copyright (C) 2009, Oy L M Ericsson Ab, NomadicLab <pubsub@nomadiclab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# Alternatively, this software may be distributed under the terms of the BSD
# license.
#
# See LICENSE and COPYING for more details.
#"""

S_COPYRIGHT_NEW = \
"""#
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
#"""

def update_copyright(input_file_name, input_file_type):
#    print input_file_type, input_file_name
    if input_file_name.split('/')[-1] == __file__.split('/')[-1]:
        print "Skipping self"
        return

    input_file = open(input_file_name, 'r+')
    original_text = input_file.read()

    copyright_text_old = (S_COPYRIGHT_OLD if (input_file_type == S_TYPE)
                          else C_COPYRIGHT_OLD)
    copyright_text_new = (S_COPYRIGHT_NEW if (input_file_type == S_TYPE)
                          else C_COPYRIGHT_NEW)
    
    text = original_text.replace(copyright_text_old, copyright_text_new)
    
    if text != original_text:
        input_file.seek(0)
        input_file.write(text)
        input_file.truncate(len(text));
        input_file.flush()
    input_file.close()


def main():
    import getopt
    
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "csf:h", [])
        #print(opts, args)
    except getopt.GetoptError, err:
        print(str(err))
        sys.exit(1)
    
    input_file_name = None
    input_file_type = None
    
    for o, a in opts:
        if o == "-h":
            print(str(__file__), "-c|-s -f input_file")
            sys.exit()
        elif o == "-c":
            input_file_type = C_TYPE
        elif o == "-s":
            input_file_type = S_TYPE
        elif o == "-f":
            input_file_name = a
        else:
            raise RuntimeError("Unhandled option: %r" % o)
    
    update_copyright(input_file_name, input_file_type)
    
    return 0


if __name__ == "__main__":
    main()


# Example: find . -name '*.py' -exec utils/updcopyright.py -s -f '{}' \;
# Use with caution! Always check the result (e.g.: svn diff)!!
