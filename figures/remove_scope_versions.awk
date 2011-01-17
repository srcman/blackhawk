#!/usr/bin/awk -f

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

BEGIN {
  OTHER=1;
  VERSIONS=2;

  state=OTHER;
  print "digraph G {"
}

/^?PAGE/ {
  pages[$1] = $0;
}

/->/ {        

  if (match($1, /VERS/)) {
    state=VERSIONS;

#    if (match($3, /PAGE/)) {
#      usedpages[$3] = 1;
#    }
        
    if (usedversions[$1] == 1) {
      usedpages[$3] = 1;
      print $0;
    } 
    next;
  }

  if (match($3, /VERS/)) {
    usedversions[$3] = 1;
  }

  print $0
}

/shape/ {
  if (state == VERSIONS) {
    if (usedversions[$1] == 1) {
      print $0;
    }
    next;
  }
  
  if (match($1, /PAGE/)) {
    next;
  }

  print $0;
}

END {
  for (i in usedpages) {
    print pages[i]
  }

  print "}"
}
