/*
 * Copyright (c) 2003-2024 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 *
 * #####################################################
 * #                       _oo0oo_                     #
 * #                      o8888888o                    #
 * #                      88" . "88                    #
 * #                      (| -_- |)                    #
 * #                      0\  =  /0                    #
 * #                    ___/`---'\___                  #
 * #                  .' \\|     |// '.                #
 * #                 / \\|||  :  |||// \               #
 * #                / _||||| -:- |||||- \              #
 * #               |   | \\\  -  /// |   |             #
 * #               | \_|  ''\---/''  |_/ |             #
 * #               \  .-\__  '-'  ___/-. /             #
 * #             ___'. .'  /--.--\  `. .'___           #
 * #          ."" '<  `.___\_<|>_/___.'  >' "" .       #
 * #         | | :  `- \`.;`\ _ /`;.`/ -`  : | |       #
 * #         \  \ `_.   \_ __\ /__ _/   .-` /  /       #
 * #     =====`-.____`.___ \_____/___.-`___.-'=====    #
 * #                       `=---='                     #
 * #     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   #
 * #               佛力加持      佛光普照              #
 * #  Buddha's power blessing, Buddha's light shining  #
 * #####################################################
 */

#ifndef _HTTP_REQUEST_H_
#define _HTTP_REQUEST_H_

#include "http_header.h"

#ifdef __cplusplus
extern "C" {
#endif

/* cookie management */
int          http_req_addcookie    (void * vmsg, char * name, int namelen, 
                                     char * value, int valuelen);
int          http_req_delcookie    (void * vmsg, char * name, int namelen);
int          http_req_delallcookie (void * vmsg);
HeaderUnit * http_req_getcookie    (void * vmsg, char * name, int namelen);
int          http_req_parse_cookie (void * vmsg);

/* Request-Line   = Method SP Request-URI SP HTTP-Version CRLF */
int http_req_reqline_decode (void * vmsg, char * pline, int linelen);

int http_req_reqline_encode (char * meth, int methlen, char * uri,
                              int urilen, char * ver, int verlen, frame_p frame);
int http_req_set_reqmeth    (void * vmsg, char * meth, int methlen);

int http_req_set_absuri (void * vmsg);
int http_req_set_docuri (void * vmsg, char * puri, int urilen, int decode, int instbrk);

/* resolve the uri to break down into all fields */
int http_req_set_uri (void * vmsg, char * puri, int urilen, int decode);

int http_partial_parse (void * vmsg, void * vbgn, int len);

int http_req_parse_header (void * vmsg);
int http_req_verify (void * vmsg);

int http_req_encoding (void * vmsg, int encode);

int http_req_build (void * vmsg, int encode);

int print_request (void * vmsg, FILE * fp);


#ifdef __cplusplus
}
#endif

#endif


