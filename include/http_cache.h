/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_CACHE_H_
#define _HTTP_CACHE_H_

#ifdef __cplusplus
extern "C" {
#endif

/* HTTP Cache storage system includes raw files and cache information file.
   raw files are actual origin server files cached in local storage in Web Server.
   cache information file is accompanied by the raw file. its name is extended from
   raw file with .cache. each raw file directory must have a cache directory with hiding
   attribute and all cache information files are saved here. */
 
/* cache facilities:
     Expires: Wed, 21 Oct 2020 07:28:00 GMT            (Response Header)
     Cache-Control: max-age=73202                      (Response Header)
     Cache-Control: public, max-age=73202              (Response Header)
 
     Last-Modified: Mon, 18 Dec 2019 12:35:00 GMT      (Response Header)
     If-Modified-Since: Fri, 05 Jul 2019 02:14:23 GMT  (Request Header)
 
     ETag: 627Af087-27C8-32A9E7B10F                    (Response Header)
     If-None-Match: 627Af087-27C8-32A9E7B10F           (Request Header)
*/

/* 96 bytes header of cache information file */

typedef struct cache_info_s {

    CRITICAL_SECTION cacheCS;

    char         * cache_file;
    char         * cache_tmp;

    char         * info_file;
    void         * hinfo;

    uint32         mimeid;
    uint8          body_flag;
    int            header_length;
    int64          body_length;
    int64          body_rcvlen;

    /* Cache-Control: max-age=0, private, must-revalidate
       Cache-Control: max-age=7200, public
       Cache-Control: no-cache */
    uint8          directive;     //0-max-age  1-no cache  2-no store
    uint8          revalidate;    //0-none  1-must-revalidate
    uint8          pubattr;       //0-unknonw  1-public  2-private(only browser cache)

    time_t         ctime;
    time_t         expire;
    int            maxage;
    time_t         mtime;
    char           etag[36];

    FragPack     * frag;

    int            count;

    void         * httpmgmt;
} CacheInfo;

void * cache_info_alloc ();
void   cache_info_free (void * vcacinfo);

int    cache_info_zero (void * vcacinfo);

int64  cache_info_body_length (void * vcacinfo);

int    cache_info_read (void * vcacinfo);

int    cache_info_write_meta (void * vcacinfo);
int    cache_info_write_frag (void * vcacinfo);
int    cache_info_write      (void * vcacinfo);

int    cache_info_add_frag (void * vcacinfo, int64 pos, int64 len, int complete);

int    cache_info_verify (void * vcacinfo);


int http_request_cache_init (void * vmsg);
int http_response_cache_init  (void * vmsg);

int http_request_in_cache (void * vmsg);
int http_proxy_cache_open  (void * vmsg);
int http_proxy_cache_parse (void * vmsg, void * vclimsg, int * resend);

int http_proxy_cache_complete (void * vmsg);
int http_cache_response_header (void * vmsg, void * vcacinfo);

int    http_cache_info_init  (void * vmgmt);
int    http_cache_info_clean (void * vmgmt);

void * cache_info_open   (void * vmgmt, char * cacfile);
void * cache_info_create (void * vmgmt, char * cacfile, int64 fsize);
void   cache_info_close  (void * vcacinfo);


#ifdef __cplusplus
}
#endif

#endif

