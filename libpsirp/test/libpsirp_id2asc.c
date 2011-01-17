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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>

#include <sysexits.h>
#include <getopt.h>
#include <libpsirp.h>

int verbose = 0;
int reverse = 0;

char *get_error(int x)
{
        char *errors[] = {
                "No error",
		"First argument NULL",
                "String too short",
		"void",
		"void",
		"void",
		"void",
		"void",
		"void",
		"void",
		"void",  /* 10 */
		"1st id: String too long",
		"1st id: String size mismatch (no double colon)",
		"1st id: Double colon found at misaligned offset",
                "1st id: Double colon found past the string buffer",
                "1st id: Misaligned bytes after double colon",
                "foo",
                "foo",
                "foo",
                "foo",
                "foo",  /* 20 */
		"2nd id: String too long",
		"2nd id: String size mismatch (no double colon)",
		"2nd id: Double colon found at misaligned offset",
                "2nd id: Double colon found past the string buffer",
                "2nd id: Misaligned bytes after double colon",
        };
  
        return errors[x*(-1)];
}

void usage()
{
    fprintf(stderr, "libpsirp_conversion [-e expected_error_code] "
            "[-a ID in ascii] [-z] [-v]\n");
    fprintf(stderr, "-z = do a reverse conversion\n");
    fprintf(stderr, "-v = verbose\n");
    exit(-1);
}

int main(int argc, char **argv)
{
    psirp_id_t rid, sid, rid_r, sid_r;
    char *test_str = NULL;
    char *newstr = NULL;
    int expected = 0;
    int result;
    char c;

    while((c = getopt(argc, argv, "e:a:vz")) != EOF) {
        switch(c) {
        case 'e': expected = -1 * atoi(optarg); break;
        case 'a': test_str = optarg; break;
        case 'z': reverse = 1; break;
        case 'v': verbose = 1; break;
        default:
            usage();
        }
    }

    result = psirp_atoids(&sid, &rid, test_str);
    if (reverse) {
        if (result != 0) {
            printf("ERROR: Illegal string: %s\n", test_str);
            return EX_SOFTWARE;
        }
        newstr = psirp_idstoa(&sid, &rid); 
        if (!newstr) {
            printf("ERROR: Could not reverse map IDs of string: %s\n", 
                   test_str);
            return EX_SOFTWARE;
        }
        /* Test that the converted ascii string is the same as argument.
           Requires canonicalization of the strings. We achieve this by
           reconverting the converted ascii string to binary presentation
           and by comparing memory.
           Alternatively, we could have an extra function to "inflate"
           the compressed strings, and that would require extra tests.
        */
        result = psirp_atoids(&sid_r, &rid_r, newstr);
        if (result != 0) {
            printf("ERROR: error: %2d, Converted string illegal: "
                   "%s (original: %s)\n", result, newstr, test_str);
            return EX_SOFTWARE;
        }
        
        if (memcmp(sid.id, sid_r.id, PSIRP_ID_LEN) ||
            memcmp(rid.id, rid_r.id, PSIRP_ID_LEN)) {
            printf("ERROR: Converted IDs do not match the original "
                   "string\n");
            return EX_SOFTWARE;
        }
    }
    
    
    if (result == expected) {
        if (verbose) {
            printf("OK: result=%3d: %67s\n", result, get_error(result));
            return EX_OK;
        }
        return EX_OK;
    }
    printf("ERROR: expected=%3d, result=%3d: %50s\n", expected, result,
           get_error(result));
    return EX_SOFTWARE;
}
