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

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include "../include/libpsirp.h"

void catch_sigsegv(int sig){
  printf("SIGSEGV captured!\n");
  exit(0);
}

int main(int argc, char *argv[]){

  int fd, bytes_written;  
  char *scope = "/pubsub/0000000000000000000000000000000000000000000000000000000000000000/";
  char *rid = NULL;
  char *fname = NULL;
  char *str = "debugging!";
  char *meta = "/meta";
  
  signal(SIGSEGV, catch_sigsegv);
  
  if (argc != 2){
    printf("%s RID\n", argv[0]);
    exit(-1);
  }
  
  rid = argv[1];

  /* Borrowed from psirptest */
  if (rid != NULL) {
    if (strlen(rid) != 64) {
      printf("RId length mismatch (%d, should be %d)\n",
	     strlen(rid), 64);
      return -1;
    }
  }
  
  fname = (char *) calloc(strlen(rid) + strlen(scope) + strlen(meta) + 1, sizeof(char));
  strcat(fname, scope);
  strcat(fname, rid);
  strcat(fname, meta);
  
  printf("Opening = %s\n", fname);
  
  if ((fd = open(fname, O_RDWR)) < 0){
    perror("open");
    return -1;
  }
  
  if ((bytes_written = write(fd, str, strlen(str))) < 0){
    perror("write");
    exit(-1);
  }
  
  printf("bytes written %d\n", bytes_written);
  
  return 0;
}
