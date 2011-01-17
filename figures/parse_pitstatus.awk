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

function declare_id(localid, shape, ltype, lcnt) {
  
  if (idtable[localid] == SCOPE) {
    shape = "box3d";
    ltype = "SCOPE";
    lcnt = scnt++;
  } else if (idtable[i] == DATA) {
    shape = "folder";
    ltype = "PUBLICATION";
    lcnt = pcnt++;
  } else if (idtable[i] == VERSION) {
    shape = "tab";
    ltype = "VERSION";
    lcnt = vcnt++;
  } else if (idtable[i] == PAGE) {
    shape = "note";
    ltype = "PAGE";
    lcnt = pacnt++;
  }

  if (names[localid] == 0) {
    if (idtable[i] == VERSION) {
        shortid = substr(localid, 25); # Assuming 32-byte ID and 20-byte hash
    } else if (idtable[i] == PAGE) {
        shortid = substr(localid, 25); # Assuming 32-byte ID and 20-byte hash
    } else {
        # We often use SIds and RIds that can be abbreviated
        "./atoidtoa.py "localid | getline shortid;
    }
    names[localid] = "\""ltype"\\n"shortid"\"";
#    names[localid] = ltype"_"lcnt;
  }

  printf "%s [shape=%s]\n", names[localid], shape;
}

function make_dot() {
  for (i in idtable) {
    declare_id(i);
  }

  for (i in edges) {
    split(i, ed, "_");
    if (ed[1] != ed[2]) {
      printf "%s -> %s\n", names[ed[1]], names[ed[2]];
    }
  }
}


# add edges in target array to current node's edges
function add_edges(target) {
  for (i in target) {
    edges[id "_" i] = 1;
  }
}

function do_magic() {

# PAGES do not point to anything. 
  if (type == PAGE) {
    return;
  }

  if (type == SCOPE) {
# SCOPES point to versions and to publications
    add_edges(versions);
    add_edges(pubs);
  } else if (type == VERSION) {
# VERSIONS point to pages
    add_edges(pages);
  } else if (type == DATA) {
# DATA (publications) point to versions
    add_edges(versions);
  }
}

# add to table AND/OR upgrade type!
function add_idtable(newid, newtype)
{
  oldtype = idtable[newid];
  if (newtype > oldtype) {
# upgrade type
    idtable[newid] = newtype;
  }
}

BEGIN {
  NULL=0
  NEWOBJ=1;
  TYPE_FOUND=2;

  SCOPE=6;
  DATA=5;
  VERSION=4;
  PAGE=3;

  SCOPE_PUBS=7;

  state=NULL;
  scnt=0;
  pcnt=0;
  vcnt=0;
  pacnt=0;
  ecnt=0;
  cnt=0;


  print "digraph G {";
}

/^[1-3]: / { 
  if (state != NULL) {
    do_magic();
  }
  state=NEWOBJ;
  id=$2;
  delete versions;
  delete pages;
  delete pubs;
}


# PUBLICATION TYPES

/SCOPE/ {
  if (state == NEWOBJ) {
    type=SCOPE;
    state = TYPE_FOUND;
    add_idtable(id, SCOPE);
  }
}

/PAGE/ {
  if (state == NEWOBJ) {
    type=PAGE;
    state = TYPE_FOUND;
    add_idtable(id, PAGE);
  }
}

/VERSION/ {
  if (state == NEWOBJ) {
    type=VERSION;
    state = TYPE_FOUND;
    add_idtable(id, VERSION);
  }
}

/DATA/ {
  if (state == NEWOBJ) {
    type=DATA;
    state = TYPE_FOUND;
    add_idtable(id, DATA);
  }
}


# META CONTENT


/Vers / {
# Don't list scope's versions
  if (state == TYPE_FOUND && type != SCOPE) {
    versions[$3] = 1;
    add_idtable($3, VERSION);
  }
}

/Page / {
  if (state == TYPE_FOUND) {
    pages[$3] = 1;
    add_idtable($3, PAGE);
  }
}

/Publications in this scope:/ {
  state = SCOPE_PUBS;
  next;
}

/[0-9a-fA-F]...../ {
  if (state == SCOPE_PUBS) {
    pubs[$1] = 1;
    add_idtable($1, DATA);
  }
}

/^$/ {
  if (state != NULL) {
    do_magic();
  }
  state = NULL;
}



END {
  make_dot();
  print "}";
}

