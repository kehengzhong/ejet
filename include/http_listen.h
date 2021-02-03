/*
 * Copyright (c) 2003-2020 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_LISTEN_H_
#define _HTTP_LISTEN_H_

#ifdef __cplusplus
extern "C" {
#endif

#define SERV_SERVER          1
#define SERV_UPLOAD          2
#define SERV_PROXY           4
#define SERV_FASTCGI         8

#define MATCH_DEFAULT        0
#define MATCH_EXACT          1
#define MATCH_PREFIX         2
#define MATCH_REGEX_CASE     3
#define MATCH_REGEX_NOCASE   4

typedef int    RequestDiag    (void * vmsg);
typedef int    ResponseDiag   (void * vmsg);
typedef void * HTTPCBInit     ();
typedef void   HTTPCBClean    (void * hcb);
typedef int    RequestHandler (void * cbobj, void * vmsg);


typedef struct error_page {
    char     * err400[20];  /* 40X-400 as index */
    char     * err500[20];  /* 50X-500 as index */

    char     * root;
} ErrorPage;

typedef struct http_location {
    char              * path;

    /* 0-default loc 1-exact matching 2-prefix matching 3-regex matching case censitive
       4-regex matching ignoring case */
    int                 matchtype;

    /* 1-SERV_SERVER 2-SERV_UPLOAD 4-SERV_PROXY 8-SERV_FASTCGI */
    int                 type;      //1-server 2-upload 4-proxy 8-fastcgi

    char                root[256];      //root path

    int                 indexnum;
    char              * index[8];

    char              * passurl;  //URL
    uint8               cache;
    char              * cachefile;

    arr_t             * script_list;
    void              * jsonobj;

} HTTPLoc;

void * http_loc_alloc (char * path, int type, char * root);
void   http_loc_free (void * vloc);

int http_loc_cmp_path (void * vloc, void * vpath);

int http_loc_build (void * vhost, void * jhost);


typedef struct http_host {
    char                hostname[168];
    int                 type;       //1-server 4-proxy 8-fastcgi

    char              * passurl;    //URL
    char                root[256];

    uint8               gzip;

    char              * cert;
    char              * prikey;
    char              * cacert;
    void              * sslctx;

    ErrorPage           errpage;

    /* location exact match with request path by hash_table */
    hashtab_t         * exact_loc_table;

    /* prefix matching with the request path, ploc instances 
     * stored in arr_t, but matching is used Wu-Manber algorithm */ 
    arr_t             * prefix_loc_list;
    void              * prefix_actrie;

    /* regular expression matching with the request path, ploc instance
     * stored in arr_t. traverse every member for path matching */
    arr_t             * regex_loc_list;
    arr_t             * regex_list;

    HTTPLoc           * uploadloc;
    HTTPLoc           * defaultloc;

    arr_t             * script_list;
    void              * jsonobj;

} HTTPHost;

void * http_host_alloc (char * hostname);
void   http_host_free (void * vhost);

int http_host_cmp (void * vhost, void * vname);

int http_host_build (void * vhl, void * jhl);


typedef struct http_listen {
    void              * res[2];

    char                localip[41];
    int                 port;
    uint8               forwardproxy;

    uint8               ssl_link;
    char              * cert;
    char              * prikey;
    char              * cacert;
    void              * sslctx;

    /* callback function from a dynamic library */
    char              * cblibfile;
    int                 cbargc;
    char              * cbargv[16];
    void              * cbhandle;

    HTTPCBInit        * cbinit;
    RequestHandler    * cbfunc;
    HTTPCBClean       * cbclean;
    void              * cbobj;

    void              * mlisten;

    hashtab_t         * host_table;
    HTTPHost          * defaulthost;

    RequestDiag       * reqdiag;
    void              * reqdiagobj;

    arr_t             * script_list;
    void              * jsonobj;
    void              * httpmgmt;
} HTTPListen;


void * http_listen_alloc (char * localip, int port, int ssl, char * cblibfile);
void   http_listen_free (void * vhl);

void * http_listen_ssl_ctx_get (void * vhl, void * vcon);
void * http_listen_get_host    (void * vhl, char * servname);

int    http_listen_init    (void * vmgmt);
int    http_listen_cleanup (void * vmgmt);

void * http_listen_add (void * vmgmt, char * localip, int port, int ssl, char * libfile);

int    http_listen_start (void * vmgmt);
void * http_listen_find  (void * vmgmt, int port);
int    http_listen_stop  (void * vmgmt, int port);
int    http_listen_check_self (void * vmgmt, char * host, int hostlen, char * dstip, int dstport);

int    http_listen_build (void * vmgmt);

void * http_host_instance   (void * vmsg);
void * http_loc_instance    (void * vmsg);
int    http_loc_passurl_get (void * vmsg, int servtype, char * url, int urllen);

int    http_real_file (void * vmsg, char * path, int len);
int    http_real_path (void * vmsg, char * path, int len);

#ifdef __cplusplus
}
#endif

#endif

