/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_RESPONSE_H_
#define _HTTP_RESPONSE_H_

#ifdef __cplusplus
extern "C" {
#endif

int http_res_getstatus (void * vmsg);

int http_res_status_decode (void * vmsg, char * pline, int linelen);
int http_res_status_encode (void * vmsg, frame_p frame);
int http_res_statusline_set (void * vmsg, char * ver, int verlen, int status, char * defreason);

int http_res_parse_header (void * vmsg, int has_statusline);

int http_res_encoding (void * vmsg);

int print_response (void * vmsg, FILE * fp);

#ifdef __cplusplus
}
#endif

#endif

