/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_MGMT_H_
#define _HTTP_MGMT_H_

#include "http_listen.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HTTP module role definition */
#define HTTP_SERVER       0x01
#define HTTP_CLIENT       0x02
#define HTTP_PROXY        0x04
#define HTTP_GATEWAY      0x08

typedef int    HTTPObjInit    (void * httpmgmt, void * vobj, void * hconf);
typedef int    HTTPObjClean   (void * vobj);

extern char * g_http_version;
extern char * g_http_build;
extern char * g_http_author;


typedef struct http_mgmt_ {

    char       * uri_unescape_char;       /* uri not escaped character list using percent encoding */
    char       * cookie_file;

    int          conn_check_interval;
    int          srv_check_interval;

    int          cli_max_header_size;
    uint8        cli_body_cache;
    int          cli_body_cache_threshold;
    int          cli_keepalive_time;      /* after one/more requests handled, keep connection */
    int          cli_conn_idle_time;      /* connection accepted, but no request bytes recv */ 
    int          cli_header_idletime;     /* after recv partial header, max time not got followed bytes */
    int          cli_header_time;         /* max time got one complete header */ 
    int          cli_request_handle_time; /* max time request arrived and handled */ 

    int          srv_max_header_size;
    int          srv_connecting_time;     /* max time that builds TCP connection to remote server  */
    int          srv_keepalive_time;      /* keep the connection alive waiting for the new httpmsg */
    int          srv_conn_idle_time;      /* max time handling HTTPMsg, in sending or waiting resp */ 

    char       * srv_con_cert;            /* cert needed when issuing HTTP request to origin over SSL con */
    char       * srv_con_prikey;          /* private key needed when issuing HTTP request over SSL con */
    char       * srv_con_cacert;          /* CA cert when client authentication needed */

    char       * srv_resp_root;
    uint8        srv_resp_cache;
    char       * srv_resp_cache_file;

    uint8        proxy_tunnel;            /* when acting as proxy, CONNECT method is suported or not */
    int          tunnel_keepalive_time;   /* max idle time there is no sending/receiving on the connection */
    uint8        auto_redirect;           /* 301/302 from origin is redirected or not by web server */
    int          proxy_buffer_size;       /* max size of data piled up in sending buffer to client */

    int          fcgi_keepalive_time;     /* FCGI TCP connection is kept alive waiting for new FcgiMsg */
    int          fcgi_connecting_time;    /* allowed max time to build TCP connection to FCGI Server   */
    int          fcgi_conn_idle_time;     /* max time handling one FcgiMsg, in sending or waiting resp */
    int          fcgi_srv_alive_time;     /* FCGI Server Instance is kept alive waiting for new FcgiCon */
    int          fcgi_buffer_size;        /* max size of data piled up in sending buffer to client */


    void             * cnfjson;
    char               root_path[256];

    char               httpver0[12];
    char               httpver1[12];
    int                header_num;
    char               useragent[256];

    uint32             uri_bitmask[8];

    int                addrnum;
    AddrItem           localaddr[6];

    char               uploadso[33];
    char               uploadvar[33];
    char               shellcmdso[33];
    char               shellcmdvar[33];
    time_t             inlaststamp;
    char               inipaddr[41];

    void             * variable;
    int                varnum;
    int                varsize;
    hashtab_t        * var_table;

    void             * source_proxy_mgmt;
    void             * host_proxy_mgmt;

    void             * httplog;

    ulong              conid;
    CRITICAL_SECTION   conCS;
    hashtab_t        * con_table;

    ulong              srvid;
    CRITICAL_SECTION   srvCS;
    rbtree_t         * srv_tree;

    void             * srv_sslctx;

    ulong              msgid;
    CRITICAL_SECTION   msgidCS;
    int                msgextsize;

    CRITICAL_SECTION   msgtableCS;
    hashtab_t        * msg_table;

    CRITICAL_SECTION   fcgisrvCS;
    hashtab_t        * fcgisrv_table;

    void             * cachemgmt; 
    void             * cookiemgmt;

    CRITICAL_SECTION   cacinfoCS;
    hashtab_t        * cacinfo_table;

    bpool_t          * con_pool;
    bpool_t          * srv_pool;
    bpool_t          * msg_pool;
    bpool_t          * header_unit_pool;
    bpool_t          * frame_pool;

    mpool_t          * fcgisrv_pool;
    mpool_t          * fcgicon_pool;
    mpool_t          * fcgimsg_pool;

    hashtab_t        * status_table;

    /* HTTPListen instances list */
    CRITICAL_SECTION   listenlistCS;
    arr_t            * listen_list;

    /* matching next proxy host and port when sending request */
    arr_t            * sndpxy_list;

    /* default MIME table */
    void             * mimemgmt;
    uint8              mimemgmt_alloc;
    void             * appmime;

    HTTPCBHandler    * req_handler;
    void             * req_cbobj;

    HTTPCBHandler    * req_check;
    void             * req_checkobj;

    HTTPCBHandler    * res_check;
    void             * res_checkobj;

    void             * xmlmgmt;
    void             * pcore;

    CRITICAL_SECTION   countCS;
    struct timeval     count_tick;
    uint64             total_recv;
    uint64             total_sent;
	

    /* reserved extra object for application */
    HTTPObjInit      * objinit;
    void             * hobjconf;
    HTTPObjClean     * objclean;
    uint8              extdata[1];

} HTTPMgmt;


int    http_mgmt_get_conf (void * vmgmt);

void * http_mgmt_alloc    (void * epump, char * jsonconf, int extsize, int msgextsize);
int    http_mgmt_init     (void * vmgmt);
int    http_mgmt_cleanup  (void * vmgmt);

int    http_mgmt_obj_init  (void * vmgmt, HTTPObjInit * objinit, void * hconf);
int    http_mgmt_obj_clean (void * vmgmt, HTTPObjClean * objclean);
void * http_mgmt_obj       (void * vmgmt);

void   http_overhead       (void * vmgmt, uint64 * recv, uint64 * sent,
                             struct timeval * lasttick, int reset, struct timeval * curt);
void   http_overhead_sent  (void * vmgmt, long sent);
void   http_overhead_recv  (void * vmgmt, long recv);

int    http_listen_check (void * vmgmt, void * vobj, int event, int fdtype);

void   http_uri_escape_init (void * vmgmt);

int    http_set_reqhandler (void * vmgmt, HTTPCBHandler * reqhandler, void * cbobj);

int    http_set_reqcheck (void * vmgmt, HTTPCBHandler * reqcheck, void * checkobj);
int    http_set_rescheck (void * vmgmt, HTTPCBHandler * rescheck, void * checkobj);

int    http_mgmt_con_add (void * vmgmt, void * vcon);
void * http_mgmt_con_get (void * vmgmt, ulong conid);
void * http_mgmt_con_del (void * vmgmt, ulong conid);
int    http_mgmt_con_num (void * vmgmt);

void * http_msg_fetch (void * vmgmt);
int    http_msg_num   (void * vmgmt);

void * http_get_json_conf (void * vmgmt);
void * http_get_mimemgmt (void * vmgmt);
void * http_get_frame_pool (void * vmgmt);

void * http_get_epump (void * vmgmt);
int    http_set_epump (void * vmgmt, void * pcore);

char * http_get_mime (void * vmgmt, char * file, uint32 * mimeid);

int    http_conf_mime_init (void * vmgmt);
int    http_conf_mime_clean (void * vmgmt);

#ifdef __cplusplus
}
#endif

#endif

