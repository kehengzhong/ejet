/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_DO_H_
#define _HTTP_DO_H_

#ifdef __cplusplus
extern "C" {
#endif

/* auto-redirect to new Location when response status is 301/302 */
int    http_redirect_request (void * vmsg);
 
/* sending HTTP Request to HTTPServer and receiving the response */
int    do_http_request (void * vmsg);
 
void * do_http_get_msg (void * vmgmt, char * url, int urllen,
                        void * resfunc, void * para, void * cbval,
                        void * rcvprocfunc, void * procpara, uint64 proccbval,
                        char * resfile, long resoff);

void * do_http_get     (void * vmgmt, char * url, int urllen,
                        void * resfunc, void * para, void * cbval,
                        void * rcvprocfunc, void * procpara, uint64 proccbval,
                        char * resfile, long resoff);
 
void * origin_http_get (void * vmgmt, char * url, int urllen,
                        void * resfunc, void * para, void * cbval,
                        void * rcvprocfunc, void * procpara, uint64 proccbval,
                        char * resfile, long resoff, uint64 start, uint64 size,
                        char * route, char * opaque);
 
 
void * do_http_post_msg (void * vmgmt, char * url, int urllen, char * mime,
                         char * body, int bodylen,
                         char * fname, long offset, long length,
                         void * resfunc, void * para, void * cbval,
                         void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                         void * sndprocfunc, void * sndpara, uint64 sndcbval,
                         char * resfile, long resoff);
 
void * do_http_post (void * vmgmt, char * url, int urllen, char * mime,
                     char * body, int bodylen,
                     char * fname, long offset, long length,
                     void * resfunc, void * para, void * cbval,
                     void * rcvprocfunc, void * rcvpara, uint64 rcvcbval,
                     void * sndprocfunc, void * sndpara, uint64 sndcbval,
                     char * resfile, long resoff);
 
#ifdef __cplusplus
}
#endif

#endif


