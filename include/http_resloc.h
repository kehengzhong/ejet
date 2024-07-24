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

#ifndef _HTTP_RESLOC_H_
#define _HTTP_RESLOC_H_

#ifdef __cplusplus
extern "C" {
#endif

#define SERV_SERVER          1
#define SERV_UPLOAD          2
#define SERV_PROXY           4
#define SERV_FASTCGI         8
#define SERV_CALLBACK        16

#define MATCH_DEFAULT        0
#define MATCH_EXACT          1
#define MATCH_PREFIX         2
#define MATCH_PREFIX_DEFAULT 3
#define MATCH_REGEX_CASE     4
#define MATCH_REGEX_NOCASE   5

typedef void * HTTPCBInit     (void * httpmgmt, int argc, char ** argv);
typedef void   HTTPCBClean    (void * hcb);
typedef int    HTTPCBHandler  (void * cbobj, void * vmsg, char * tplfile);


typedef struct error_page {
    char     * err400[20];  /* 40X-400 as index */
    char     * err500[20];  /* 50X-500 as index */

    char     * root;
} ErrorPage;

#define LBA_UNKNOWN            0
#define LBA_ROUND_ROBIN        1
#define LBA_WEIGHT             2
#define LBA_FAST_TRANSACT      3
#define LBA_LEAST_CONN         4
#define LBA_CONSIST_HASH       5
#define LBA_PATTERN_MATCH      6

typedef struct pass_url_s {
    char              * url;
    int                 urllen;

    uint8               loadbal;

    char              * lbfields;
    int                 lbflen;

    CRITICAL_SECTION    passCS;
    ulong               passcnt;

    long                weight;
    uint8               weight_changed;

    arr_t             * url_list;
    arr_t             * back_url_list;
    arr_t             * down_url_list;

    time_t              srv_tick;

} PassURL;

void * passurl_alloc ();
void   passurl_free (void * vpu);

int    passurl_set_loadbal (void * vpu, char * loadbal, int len);
int    passurl_set_lbfields (void * vpu, char * lbfields, int lbflen);
int    passurl_set_url (void * vpu, char * url, int len);

int    passurl_add_passitem (void * vpu, void * vpi);

int    passurl_get (void * vmsg, char ** passurl, int * len);

void passurl_print (void * vpu, FILE * fp);


typedef struct http_location {
    char              * path;

    char                root[256];      //root path

    /* indicates that path is allocated and need to be freed when cleaning resources */
    unsigned            path_dup  : 2;

    /* 0-default loc 1-exact matching 2-prefix matching 3-regex matching case censitive
       4-regex matching ignoring case */
    unsigned            matchtype : 4;

    /* 1-SERV_SERVER 2-SERV_UPLOAD 4-SERV_PROXY 8-SERV_FASTCGI */
    unsigned            type      : 16;      //1-server 2-upload 4-proxy 8-fastcgi 16-callback

    //0-do not show file list of given path  1-show file list of accessing path
    unsigned            show_file_list : 1;

    //0-do not auto redirect when receiving 301/302 response in proxy  1-auto redirect
    unsigned            auto_redirect : 1;

    unsigned            indexnum  : 4;

    char              * index[8];

    //char              * passurl;  //URL
    PassURL           * passurl;

    uint8               cache;
    char              * cachefile;

    arr_t             * script_list;
    arr_t             * reply_script_list;
    arr_t             * cache_check_script_list;
    arr_t             * cache_store_script_list;

    void              * jsonobj;

    HTTPCBHandler     * cbfunc;
    void              * cbobj;
    char              * tplfile;

} HTTPLoc;

void * http_loc_alloc (char * path, int pathlen, uint8 pathdup, int matchtype, int servtype, char * root);
void   http_loc_free  (void * vloc);

int http_loc_set_root (void * vloc, char * root, int rootlen);
int http_loc_set_index (void * vloc, char ** indexlist, int num);
int http_loc_set_proxy (void * vloc, char * passurl, char * cachefile);
int http_loc_set_fastcgi (void * vloc, char * passurl);

int http_loc_cmp_path (void * vloc, void * vpath);

int http_loc_build (void * vhost, void * jhost);


typedef struct http_host {
    char                hostname[168];
    int                 port;

    int                 maxcon;

    /* 0-default host 1-exact matching 2-prefix matching 3-regex matching case censitive
       4-regex matching ignoring case */
    unsigned            matchtype : 4;

    unsigned            indexnum  : 4;

    //0-do not auto redirect when receiving 301/302 response in proxy  1-auto redirect
    unsigned            auto_redirect : 1;

    unsigned            proxy : 2;
    unsigned            cache : 2;

    char              * index[8];

    /* The proxy server forwards the HTTP client request to the destination host,
       receives the response from the destination host and forwards it to the client. */
    char                proxyhost[64];
    int                 proxyport;

    //char              * passurl;    //forwarding URL, to be used in future

    char                root[256];

    char              * cachefile;

    char              * cert;
    char              * prikey;
    char              * cacert;
    void              * sslctx;

    uint8               gzip;

    ErrorPage           errpage;

    CRITICAL_SECTION    hostCS;

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

    HTTPLoc           * uploadloc;  //to be used in future
    HTTPLoc           * defaultloc;

    arr_t             * script_list;
    arr_t             * reply_script_list;
    arr_t             * cache_check_script_list;
    arr_t             * cache_store_script_list;

    void              * jsonobj;

    /* page template parsing and subsituding table */
    CRITICAL_SECTION   texttplCS;
    hashtab_t        * texttpl_tab;
    CRITICAL_SECTION   listtplCS;
    hashtab_t        * listtpl_tab;

    void             * hl;
    void             * hc;

} HTTPHost;

void * http_host_alloc (char * hostn, int hostlen);
void   http_host_free (void * vhost);

void * http_listen_host_create (void * vhl, char * hostn, int hostlen, char * root,
                                char * cert, char * prikey, char * cacert);

void * http_connect_host_create (void * vhl, char * hostn, int hostlen, int port, int matchtype,
                                 char * root, char * cert, char * prikey, char * cacert);

int http_host_cmp (void * vhost, void * vname);

int http_host_build (void * vpar, void * jobj, int partype);


typedef struct http_listen {
    void              * res[2];

    char                localip[41];
    int                 port;
    uint8               forwardproxy;

    //0-do not auto redirect when receiving 301/302 response in proxy  1-auto redirect
    uint8              auto_redirect;

    uint8               indexnum;
    char              * index[8];

    char                root[256];
    uint8               cache;
    char              * cachefile;

    uint8               ssl_link;
    char              * cert;
    char              * prikey;
    char              * cacert;
    void              * sslctx;

    /* callback function from a dynamic library */
    char              * cblibfile;
    int                 cbargc;
    char              * cbargv[16];

#ifdef UNIX
    void              * cbhandle;
#endif
#if defined(_WIN32) || defined(_WIN64)
    HMODULE             cbhandle;
#endif

    HTTPCBInit        * cbinit;
    HTTPCBHandler     * cbfunc;
    HTTPCBClean       * cbclean;
    void              * cbobj;

    void              * mlisten;

    CRITICAL_SECTION    hlCS;
    hashtab_t         * host_table;
    HTTPHost          * defaulthost;

    arr_t             * script_list;
    arr_t             * reply_script_list;
    arr_t             * cache_check_script_list;
    arr_t             * cache_store_script_list;

    void              * jsonobj;
    void              * httpmgmt;
} HTTPListen;


void * http_listen_alloc (char * localip, int port, uint8 fwdpxy);
void   http_listen_free (void * vhl);

int    http_listen_ssl_ctx_set (void * vhl, char * cert, char * prikey, char * cacert);
void * http_listen_ssl_ctx_get (void * vhl);
void * http_listen_host_get    (void * vhl, char * servname);

/* callback libfile format: /opt/app/lib/appmgmt.so app.conf */
int    http_listen_cblibfile_set (void * vhl, char * cblibfile);

int    http_listen_init    (void * vmgmt);
int    http_listen_cleanup (void * vmgmt);

void * http_listen_add (void * vmgmt, char * localip, int port, uint8 fwdpxy);

int    http_listen_start_all (void * vmgmt);

void * http_ssl_listen_start (void * vmgmt, char * localip, int port, uint8 fwdpxy,
                              uint8 ssl, char * cert, char * prikey, char * cacert, char * libfile);
void * http_listen_start     (void * vmgmt, char * localip, int port, uint8 fwdpxy, char * libfile);

int    http_listen_num  (void * vmgmt);
void * http_listen_get  (void * vmgmt, int index);

void * http_listen_find (void * vmgmt, char * localip, int port);
int    http_listen_stop (void * vmgmt, char * localip, int port);

int    http_listen_check_self (void * vmgmt, char * host, int hostlen, char * dstip, int dstport);

int    http_listen_build (void * vmgmt);


typedef struct http_connect_s {

    int                max_header_size;
    int                connecting_time; /* max time that builds TCP connection to remote server  */
    int                keepalive_time;  /* keep the connection alive waiting for the new httpmsg */
    int                conn_idle_time;  /* max time handling HTTPMsg, in sending or waiting resp */

    //0-do not auto redirect when receiving 301/302 response in proxy  1-auto redirect
    uint8              auto_redirect;

    uint8              indexnum;
    char             * index[8];

    char             * cert;      /* cert needed when issuing HTTP request to origin over SSL con */
    char             * prikey;    /* private key needed when issuing HTTP request over SSL con */
    char             * cacert;    /* CA cert when client authentication needed */
    void             * sslctx;

    char               root[256];
    uint8              cache;
    char             * cachefile;

    CRITICAL_SECTION   hcCS;

    /* exact matching host with request host by hash_table */
    hashtab_t         * exact_host_table;

    /* prefix matching with the request host, phost instances 
     * stored in arr_t, but matching is used Wu-Manber algorithm */
    arr_t             * prefix_host_list;
    void              * prefix_host_actrie;

    /* regular expression matching with the request host, phost instance
     * stored in arr_t. traverse every member for host matching */
    arr_t             * regex_host_list;  //stored phost instance
    arr_t             * regex_list;       //stored regex handle

    arr_t            * script_list;
    arr_t            * reply_script_list;
    arr_t            * cache_check_script_list;
    arr_t            * cache_store_script_list;

    void             * jsonobj;

} HTTPConnect;

void * http_connect_alloc ();
void   http_connect_free (void * vhc);

int    http_connect_host_add (void * vhc, void * vhost);
void * http_connect_host_find (void * vhc, char * host, int hostlen, int port);

int    http_connect_sslctx_set (void * vhc, char * cert, char * prikey, char * cacert);
void * http_connect_sslctx_get (void * vhc);

int    http_connect_init    (void * vmgmt);
int    http_connect_cleanup (void * vmgmt);

int    http_connect_build (void * vmgmt);

/* Here are some interface functions to get or set the resource location. */

void * http_host_instance   (void * vmsg);
void * http_loc_instance    (void * vmsg);
int    http_loc_passurl_get (void * vmsg, int servtype, char * url, int urllen);

int    http_real_file (void * vmsg, char * path, int len);
int    http_real_path (void * vmsg, char * path, int len);


void * http_prefix_loc (void * vhl, char * hostn, int hostlen, char * matstr, int len,
                        char * root, void * cbfunc, void * cbobj, void * tplfile);

void * http_exact_loc (void * vhl, char * hostn, int hostlen, char * matstr, int len,
                       char * root, void * cbfunc, void * cbobj, void * tplfile) ;

void * http_regex_loc (void * vhl, char * hostn, int hostlen, char * matstr, int len, int ignorecase,
                       char * root, void * cbfunc, void * cbobj, void * tplfile);

int    http_loc_cache_get (void * vmsg, uint8 * cached, char ** cafn, int * cafnlen, char ** root, int * rootlen);

#ifdef __cplusplus
}
#endif

#endif

