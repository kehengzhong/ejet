/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_SCRIPT_H_
#define _HTTP_SCRIPT_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct http_script_s {
    void        * msg;

    char        * script;
    int           scriptlen;

    /* 0-unknown  1-HTTPListen script  2-Host script  3-Location script  */
    uint8         sctype   : 4;
    uint8         replied  : 1;
    uint8         exitflag : 1;
    uint8         reloc    : 1;
    uint8         alloc    : 1;

    char        * retval;
    int           retvallen;

    char        * vname;
    int           vtype;

} http_script_t, HTTPScript;

void * http_script_alloc ();
int    http_script_init (void * vhsc, void * vmsg, char * psc, int sclen, uint8 sctype, char * vname, int vtype);
void   http_script_free (void * vhsc);

int http_script_parse_exec (void * vhsc, char * sc, int sclen);

int http_script_segment_exec (void * vmsg, char * psc, int sclen, char ** pval,
                              int * vallen, char * vname, int vtype);
int http_script_exec (void * vmsg);

int http_reply_script_exec (void * vmsg);


void   script_parser_init  ();
void   script_parser_clean ();

void * script_parser_get   (char * cmd, int len);

#ifdef __cplusplus
}
#endif

#endif

