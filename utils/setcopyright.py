#!/usr/bin/env python


import sys


C_TYPE = '*'
S_TYPE = '#'

C_COPYRIGHT = \
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

S_COPYRIGHT = \
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
#
"""


def update_copyright(input_file_name, input_file_type):
    input_file = open(input_file_name, 'r+')
    original_text = input_file.read()
    text = original_text
    
    if input_file_type == C_TYPE: # C files (e.g. .c, .h, .i)
        p1 = text.partition("/*")
        
        if p1[1] == '' or not (p1[0] == '' or p1[0].endswith('\n')):
            print("Adding copyright to: %s" % input_file_name)
            text = C_COPYRIGHT + '\n\n' + text
        else:
            print("Changing copyright in: %s" % input_file_name)
            p2 = p1[2].partition("*/")
            
            if p2[1] == '':
                raise RuntimeError("Bad input: %s" % input_file_name)
            text = p1[0] + C_COPYRIGHT + p2[2]
    
    elif input_file_type == S_TYPE: # "Script files" (e.g. .py, .sh)
        lines = text.splitlines(True)
        copyright_lines = S_COPYRIGHT.splitlines(True)
        shell_index = None
        copyright_start_index = None
        copyright_end_index = None
        
        for i in xrange(len(lines)):
            if copyright_start_index is None:
                if lines[i].startswith('#'):
                    if lines[i][1] == '!':
                        shell_index = i
                    else:
                        copyright_start_index = i
            else:
                if not lines[i].startswith('#'):
                    copyright_end_index = i
                    break
        
        if copyright_start_index is None:
            print("Adding copyright to: %s" % input_file_name)
            if shell_index is None:
                lines = copyright_lines + ["\n"] + lines
            else:
                lines = \
                    lines[:shell_index+1] + \
                    ["\n"] + copyright_lines + \
                    lines[shell_index+1:]
        elif copyright_end_index is not None:
            print("Changing copyright in: %s" % input_file_name)
            lines = \
                lines[:copyright_start_index] + \
                copyright_lines + \
                lines[copyright_end_index:]
        else:
            raise RuntimeError("Bad input: %s" % input_file_name)
        
        text = "".join(lines)
    
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
            assert False, "Unhandled option: %r" % o
    
    update_copyright(input_file_name, input_file_type)
    
    return 0


if __name__ == "__main__":
    main()


# Example: find . -name '*.py' -exec utils/setcopyright.py -s -f '{}' \;
# Use with caution! Always check the result (e.g.: svn diff)!!
