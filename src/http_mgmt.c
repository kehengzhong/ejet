/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"

#include "http_header.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_srv.h"
#include "http_con.h"
#include "http_listen.h"
#include "http_status.h"
#include "http_sndpxy.h"
#include "http_pump.h"
#include "http_request.h"
#include "http_response.h"
#include "http_handle.h"
#include "http_cookie.h"
#include "http_ssl.h"
#include "http_variable.h"
#include "http_fcgi_srv.h"
#include "http_log.h"
#include "http_cache.h"
#include "http_script.h"

char * g_http_version = "1.2.12";
char * g_http_build = "eJet/1.2.12 Web Server built "__DATE__" "__TIME__" "
                      "by kehengzhong@hotmail.com";
char * g_http_author = "Lao Ke <kehengzhong@hotmail.com>";

HTTPMgmt * gp_httpmgmt = NULL;

int http_mgmt_get_conf (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    char       key[256];
    int        keylen = 0;
    int        ret = 0;

    char     * pstr = NULL;

    if (!mgmt) return -1;

    mgmt->conn_check_interval = 3;
    mgmt->srv_check_interval = 5;

    /* when receiving client request, configuration as following */

    sprintf(key, "http.url not escape char");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&mgmt->uri_unescape_char, NULL);
    if (ret <= 0)
        mgmt->uri_unescape_char = "-_.~!*'();:@&=+$,/?#][";

    sprintf(key, "http.cookie file");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&mgmt->cookie_file, NULL);
    if (ret <= 0)
        mgmt->cookie_file = "./cookie.txt";

    sprintf(key, "http.receive request.max header size");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->cli_max_header_size);
    if (ret <= 0)
        mgmt->cli_max_header_size = 32*1024;

    sprintf(key, "http.receive request.body cache");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&pstr, NULL);
    if (ret <= 0 || !pstr) mgmt->cli_body_cache = 0;
    if (pstr && strcasecmp(pstr, "on") == 0)
        mgmt->cli_body_cache = 1;
    else
        mgmt->cli_body_cache = 0;

    sprintf(key, "http.receive request.body cache threshold");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->cli_body_cache_threshold);
    if (ret <= 0)
        mgmt->cli_body_cache_threshold = 64*1024;

    sprintf(key, "http.receive request.keepalive timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->cli_keepalive_time);
    if (ret <= 0)
        mgmt->cli_keepalive_time = 30;

    sprintf(key, "http.receive request.connection idle timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->cli_conn_idle_time);
    if (ret <= 0)
        mgmt->cli_conn_idle_time = 10;

    sprintf(key, "http.receive request.header idle timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->cli_header_idletime);
    if (ret <= 0)
        mgmt->cli_header_idletime = 10;

    sprintf(key, "http.receive request.header timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->cli_header_time);
    if (ret <= 0)
        mgmt->cli_header_time = 30;

    sprintf(key, "http.receive request.request handle timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->cli_request_handle_time);
    if (ret <= 0)
        mgmt->cli_request_handle_time = 180;

    /* when sending request to remote origin server, configuration as following */

    sprintf(key, "http.send request.max header size");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->srv_max_header_size);
    if (ret <= 0)
        mgmt->srv_max_header_size = 32*1024;

    sprintf(key, "http.send request.connecting timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->srv_connecting_time);
    if (ret <= 0)
        mgmt->srv_connecting_time = 8;

    sprintf(key, "http.send request.keepalive timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->srv_keepalive_time);
    if (ret <= 0)
        mgmt->srv_keepalive_time = 10;

    sprintf(key, "http.send request.connection idle timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->srv_conn_idle_time);
    if (ret <= 0)
        mgmt->srv_conn_idle_time = 180;

    /* When seinding request to origin server by HTTPS/SSL connection, current web server
       will served as SSL client. if strict client authentication is required by SSL peer,
       the certificate, private key and CA verifying chain certificates will be provided. */

    sprintf(key, "http.send request.ssl certificate");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&mgmt->srv_con_cert, NULL);
    if (ret <= 0)
        mgmt->srv_con_cert = NULL;

    sprintf(key, "http.send request.ssl private key");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&mgmt->srv_con_prikey, NULL);
    if (ret <= 0)
        mgmt->srv_con_prikey = NULL;

    sprintf(key, "http.send request.ssl ca certificate");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&mgmt->srv_con_cacert, NULL);
    if (ret <= 0)
        mgmt->srv_con_cacert = NULL;

    sprintf(key, "http.send request.root");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&mgmt->srv_resp_root, NULL);
    if (ret <= 0)
        mgmt->srv_resp_root = NULL;

    sprintf(key, "http.send request.cache");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&pstr, NULL);
    if (ret <= 0 || !pstr) mgmt->srv_resp_cache = 0;
    if (pstr && strcasecmp(pstr, "on") == 0)
        mgmt->srv_resp_cache = 1;
    else
        mgmt->srv_resp_cache = 0;

    sprintf(key, "http.send request.cache file");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&mgmt->srv_resp_cache_file, NULL);
    if (ret <= 0)
        mgmt->srv_resp_cache_file = NULL;

    /* proxy configuration */

    sprintf(key, "http.proxy.connect tunnel");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&pstr, NULL);
    if (ret <= 0 || !pstr) mgmt->proxy_tunnel = 0;
    if (pstr && strcasecmp(pstr, "on") == 0)
        mgmt->proxy_tunnel = 1;
    else
        mgmt->proxy_tunnel = 0;

    sprintf(key, "http.proxy.tunnel keepalive timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->tunnel_keepalive_time);
    if (ret <= 0)
        mgmt->tunnel_keepalive_time = 60;

    sprintf(key, "http.proxy.auto redirect");  keylen = strlen(key);
    ret = json_mgetP(mgmt->cnfjson, key, keylen, (void **)&pstr, NULL);
    if (ret <= 0 || !pstr) mgmt->auto_redirect = 0; 
    if (pstr && strcasecmp(pstr, "on") == 0)  
        mgmt->auto_redirect = 1;            
    else          
        mgmt->auto_redirect = 0;

    sprintf(key, "http.proxy.buffer size");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->proxy_buffer_size);
    if (ret <= 0)
        mgmt->proxy_buffer_size = 256*1024;

    /* FastCGI interface parameters, maintaining TCP/UnixSock connection to FCGI server */

    sprintf(key, "http.fastcgi.connecting timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->fcgi_connecting_time);
    if (ret <= 0)
        mgmt->fcgi_connecting_time = 10;
 
    sprintf(key, "http.fastcgi.keepalive timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->fcgi_keepalive_time);
    if (ret <= 0)
        mgmt->fcgi_keepalive_time = 30;
 
    sprintf(key, "http.fastcgi.connection idle timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->fcgi_conn_idle_time);
    if (ret <= 0)
        mgmt->fcgi_conn_idle_time = 90;

    sprintf(key, "http.fastcgi.fcgi server alive timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->fcgi_srv_alive_time);
    if (ret <= 0)
        mgmt->fcgi_srv_alive_time = 120;
 
    sprintf(key, "http.fastcgi.buffer size");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->fcgi_buffer_size);
    if (ret <= 0)
        mgmt->fcgi_buffer_size = 256*1024;

    return 0;
}


void * http_mgmt_alloc (void * pcore, char * confname, int extsize, int msgextsize)
{
    HTTPMgmt * mgmt = NULL;

    if (extsize < 1) extsize = 1;
    if (msgextsize < 1) msgextsize = 1;

    mgmt = (HTTPMgmt *)kzalloc(sizeof(*mgmt) - 1 + extsize);
    if (!mgmt) return NULL;

    tolog(0, "\n");
    tolog(1, "eJet - HTTP module allocated.\n");

    strcpy(mgmt->httpver0, "HTTP/1.0");
    strcpy(mgmt->httpver1, "HTTP/1.1");
    mgmt->header_num = 71;
    sprintf(mgmt->useragent, "eJet/%s", g_http_version);

    mgmt->addrnum = get_selfaddr(6, mgmt->localaddr);

    mgmt->cnfjson = json_init(1, 1, 1);
    if (confname) {
        json_decode_file(mgmt->cnfjson, confname, strlen(confname), 0, 0);
    }
    http_mgmt_get_conf(mgmt);

    tolog(1, "eJet - Json Conf '%s' read.\n", confname);

    file_abspath(confname, mgmt->root_path, sizeof(mgmt->root_path)-1);

#ifdef UNIX
    chdir(mgmt->root_path);
#elif defined(_WIN32) || defined(_WIN64)
    SetCurrentDirectory(mgmt->root_path);
#endif

    tolog(1, "eJet - Working Path '%s' set\n", mgmt->root_path);

    mgmt->mimemgmt_alloc = 0;

    GetRandStr(mgmt->uploadso, 18, 0);
    GetRandStr(mgmt->shellcmdso, 20, 0);
    GetRandStr(mgmt->uploadvar, 10, 0);
    GetRandStr(mgmt->shellcmdvar, 8, 0);

    strcat((char *)mgmt->uploadso, ".so");
    strcat((char *)mgmt->shellcmdso, ".so");

    mgmt->msgextsize = msgextsize;
    mgmt->pcore = pcore;

    gp_httpmgmt = mgmt;

    return mgmt;
}

int http_mgmt_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

#ifdef HAVE_OPENSSL
    http_ssl_library_init();
#endif

    http_uri_escape_init(mgmt);
   
    http_send_proxy_init(mgmt);

    if (mgmt->msgextsize <= 0) mgmt->msgextsize = 1;

    mgmt->httplog = http_log_init(mgmt);

    mgmt->conid = 1;
    InitializeCriticalSection(&mgmt->conCS);
    mgmt->con_table = ht_only_new(800, http_con_cmp_conid);
    ht_set_hash_func(mgmt->con_table, http_con_hash_func);

    mgmt->msgid = 0;
    InitializeCriticalSection(&mgmt->msgidCS);
    InitializeCriticalSection(&mgmt->msgtableCS);
    mgmt->msg_table = ht_only_new(600, http_msg_cmp_msgid);
    ht_set_hash_func(mgmt->msg_table, http_msg_hash_msgid);

    if (!mgmt->con_pool) { 
        mgmt->con_pool = bpool_init(NULL);
        bpool_set_initfunc (mgmt->con_pool, http_con_init);
        bpool_set_freefunc (mgmt->con_pool, http_con_free);
        bpool_set_unitsize(mgmt->con_pool, sizeof(HTTPCon));
        bpool_set_allocnum(mgmt->con_pool, 64);
    } 

    if (!mgmt->msg_pool) {
        mgmt->msg_pool = bpool_init(NULL);
        bpool_set_freefunc(mgmt->msg_pool, http_msg_free);
        bpool_set_unitsize(mgmt->msg_pool, sizeof(HTTPMsg) - 1 + mgmt->msgextsize);
        bpool_set_allocnum(mgmt->msg_pool, 128);
    }

    if (!mgmt->header_unit_pool) {
        mgmt->header_unit_pool = bpool_init(NULL);
        bpool_set_freefunc(mgmt->header_unit_pool, hunit_free);
        bpool_set_unitsize(mgmt->header_unit_pool, sizeof(HeaderUnit));
        bpool_set_allocnum(mgmt->header_unit_pool, 256);
    }

    if (!mgmt->frame_pool) {
        mgmt->frame_pool = bpool_init(NULL);
        bpool_set_initfunc(mgmt->frame_pool, frame_empty);
        bpool_set_freefunc(mgmt->frame_pool, frame_free);
        bpool_set_unitsize(mgmt->frame_pool, sizeof(frame_t));
        bpool_set_allocnum(mgmt->frame_pool, 64);
        //bpool_set_getsizefunc(mgmt->frame_pool, frame_size);
        //bpool_set_freesize(mgmt->frame_pool, 32*1024);
    }

    if (!mgmt->mimemgmt) {
        mgmt->mimemgmt = mime_type_init();
        mgmt->mimemgmt_alloc = 1;
    }
    http_conf_mime_init(mgmt);

    http_cache_info_init(mgmt);

    http_var_init(mgmt);

    http_status_init(mgmt);
    http_mgmt_srv_init(mgmt);

    if (mgmt->srv_sslctx == NULL) {
#ifdef HAVE_OPENSSL
        mgmt->srv_sslctx = http_ssl_client_ctx_init(mgmt->srv_con_cert,
                                   mgmt->srv_con_prikey, mgmt->srv_con_cacert);
#endif
    }

    InitializeCriticalSection(&mgmt->countCS);
    gettimeofday(&mgmt->count_tick, NULL);
    mgmt->total_recv = 0;
    mgmt->total_sent = 0;

    if (mgmt->objinit) 
        (*mgmt->objinit)(mgmt, &mgmt->extdata[0], mgmt->hobjconf);

    http_mgmt_fcgisrv_init(mgmt);

    mgmt->cookiemgmt = cookie_mgmt_alloc(mgmt, mgmt->cookie_file);

    script_parser_init();

    http_listen_init(mgmt);

    tolog(0, "\n");
    return 0;
}


int http_mgmt_cleanup (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    
    if (!mgmt) return -1;

    tolog(0, "\n");

    script_parser_clean();

    http_var_free(mgmt);

    if (mgmt->srv_sslctx) {
#ifdef HAVE_OPENSSL
        http_ssl_ctx_free(mgmt->srv_sslctx);
#endif
        mgmt->srv_sslctx = NULL;
    }

    http_listen_cleanup(mgmt);

    if (mgmt->mimemgmt && mgmt->mimemgmt_alloc) {
        mime_type_clean(mgmt->mimemgmt);
        mgmt->mimemgmt = NULL;
        mgmt->mimemgmt_alloc = 0;
    }
    http_conf_mime_clean(mgmt);

    DeleteCriticalSection(&mgmt->conCS);
    if (mgmt->con_table) {
        ht_free_all(mgmt->con_table, http_con_free);
        mgmt->con_table = NULL;
    }

    cookie_mgmt_free(mgmt->cookiemgmt);

    http_mgmt_srv_clean(mgmt);
    http_status_cleanup(mgmt);
    http_send_proxy_clean(mgmt);

    DeleteCriticalSection(&mgmt->msgidCS);

    DeleteCriticalSection(&mgmt->msgtableCS);
    ht_free_all(mgmt->msg_table, http_msg_free);

    http_mgmt_fcgisrv_clean(mgmt);

    if (mgmt->con_pool) {
        bpool_clean(mgmt->con_pool);
        mgmt->con_pool = NULL;
    }

    if (mgmt->msg_pool) {
        bpool_clean(mgmt->msg_pool);
        mgmt->msg_pool = NULL;
    }

    if (mgmt->header_unit_pool) {
        bpool_clean(mgmt->header_unit_pool);
        mgmt->header_unit_pool = NULL;
    }

    if (mgmt->frame_pool) {
        bpool_clean(mgmt->frame_pool);
        mgmt->frame_pool = NULL;
    }

    /* application-layer resource release now */
    if (mgmt->objclean) 
        (*mgmt->objclean)(&mgmt->extdata[0]);

    if (mgmt->httplog) {
        http_log_clean(mgmt->httplog);
        mgmt->httplog = NULL;
    }

    http_cache_info_clean(mgmt);

    mgmt->pcore = NULL;

    if (mgmt->cnfjson) {
        json_clean(mgmt->cnfjson);
        mgmt->cnfjson = NULL;
    }

    DeleteCriticalSection(&mgmt->countCS);

    gp_httpmgmt = NULL;

    kfree(mgmt);

    tolog(1, "eJet - HTTP module exited.\n");
    tolog(0, "\n");
    return 0;
}

int http_mgmt_obj_init (void * vmgmt, HTTPObjInit * objinit, void * hconf)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    mgmt->objinit = objinit;
    mgmt->hobjconf = hconf;

    return 0;
}

int http_mgmt_obj_clean (void * vmgmt, HTTPObjClean * objclean)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    mgmt->objclean = objclean;
    return 0;
}


void * http_mgmt_obj (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return NULL;

    return &mgmt->extdata[0];
}

void http_uri_escape_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    int        i, len;
 
    if (!mgmt) return;

    for (i = 0; i < 8; i++) {
        mgmt->uri_bitmask[i] = 0xFFFFFFFF;
    }

    for (i = 0; i < 26; i++) {
        bit_mask_unset(mgmt->uri_bitmask, 'a' + i);
    }

    for (i = 0; i < 26; i++) {
        bit_mask_unset(mgmt->uri_bitmask, 'A' + i);
    }

    for (i = 0; i < 10; i++) {
        bit_mask_unset(mgmt->uri_bitmask, '0' + i);
    }

    len = str_len(mgmt->uri_unescape_char);
    for (i = 0; i <len; i++) {
        bit_mask_unset(mgmt->uri_bitmask, mgmt->uri_unescape_char[i]);
    }

    tolog(1, "eJet - Bit-Mask for URI-escape/unescape set.\n");
    return;
}

void http_overhead (void * vmgmt, uint64 * recv, uint64 * sent,
                    struct timeval * lasttick, int reset, struct timeval * curt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return;
 
    EnterCriticalSection(&mgmt->countCS);
    if (recv) *recv = mgmt->total_recv;
    if (sent) *sent = mgmt->total_sent;
    if (lasttick) *lasttick = mgmt->count_tick;
    if (reset) {
        if (curt) mgmt->count_tick = *curt;
        else gettimeofday(&mgmt->count_tick, NULL);
        mgmt->total_recv = 0;
        mgmt->total_sent = 0;
    }
    LeaveCriticalSection(&mgmt->countCS);
}
 
void http_overhead_sent (void * vmgmt, long sent)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return;
 
    EnterCriticalSection(&mgmt->countCS);
    mgmt->total_sent += sent;
    LeaveCriticalSection(&mgmt->countCS);
}
 
void http_overhead_recv (void * vmgmt, long recv)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return;
 
    EnterCriticalSection(&mgmt->countCS);
    mgmt->total_recv += recv;
    LeaveCriticalSection(&mgmt->countCS);
}
 
int http_set_reqhandler (void * vmgmt, HTTPCBHandler * reqhandler, void * cbobj)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    mgmt->req_handler = reqhandler;
    mgmt->req_cbobj = cbobj;

    return 0;
}

int http_set_reqcheck(void * vmgmt, HTTPCBHandler * reqcheck, void * checkobj)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    mgmt->req_check = reqcheck;
    mgmt->req_checkobj = checkobj;

    return 0;
}

int http_set_rescheck(void * vmgmt, HTTPCBHandler * rescheck, void * checkobj)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    mgmt->res_check = rescheck;
    mgmt->res_checkobj = checkobj;

    return 0;
}


int http_mgmt_con_add (void * vmgmt, void * vcon)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = (HTTPCon *)vcon;
    
    if (!mgmt) return -1;
    if (!pcon) return -2;

    EnterCriticalSection(&mgmt->conCS);
    ht_set(mgmt->con_table, &pcon->conid, pcon);
    LeaveCriticalSection(&mgmt->conCS);

    return 0;
}

void * http_mgmt_con_get (void * vmgmt, ulong conid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;

    if (!mgmt) return NULL;

    EnterCriticalSection(&mgmt->conCS);
    pcon = ht_get(mgmt->con_table, &conid);
    LeaveCriticalSection(&mgmt->conCS);

    return pcon;
}

void * http_mgmt_con_del (void * vmgmt, ulong conid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;

    if (!mgmt) return NULL;

    EnterCriticalSection(&mgmt->conCS);
    pcon = ht_delete(mgmt->con_table, &conid);
    LeaveCriticalSection(&mgmt->conCS);

    return pcon;
}

int http_mgmt_con_num (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    int        num = 0;

    if (!mgmt) return 0;

    EnterCriticalSection(&mgmt->conCS);
    num = ht_num(mgmt->con_table);
    LeaveCriticalSection(&mgmt->conCS);

    return num;
}


void * http_msg_fetch (void * vmgmt)
{
    HTTPMgmt         * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg          * msg = NULL;

    if (!mgmt) return NULL;
   
    msg = bpool_fetch(mgmt->msg_pool);
    if (!msg) return NULL;

    EnterCriticalSection(&mgmt->msgidCS);
    msg->msgid = mgmt->msgid++;
    if (msg->msgid == 0) msg->msgid = mgmt->msgid++;
    LeaveCriticalSection(&mgmt->msgidCS);

    msg->httpmgmt = mgmt;
    msg->pcore = mgmt->pcore;

    http_msg_init(msg);
    http_msg_init_method(msg);

    http_msg_mgmt_add(mgmt, msg);

    return msg;
}

int http_msg_num (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    int        num = 0;

    if (!mgmt) return 0;

    EnterCriticalSection(&mgmt->msgtableCS);
    num = ht_num(mgmt->msg_table);
    LeaveCriticalSection(&mgmt->msgtableCS);

    return num;
}

void * http_get_json_conf (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return NULL;
 
    return mgmt->cnfjson;
}

void * http_get_mimemgmt (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return NULL;
 
    return mgmt->mimemgmt;
}
 
void * http_get_frame_pool (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return NULL;
 
    return mgmt->frame_pool;
}

void * http_get_epump (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return NULL;
 
    return mgmt->pcore;
}
 
int http_set_epump (void * vmgmt, void * pcore)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    mgmt->pcore = pcore;
    return 0;
}

char * http_get_mime (void * vmgmt, char * file, uint32 * mimeid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    char     * p = NULL;
    char     * pend = NULL;
    char     * poct = NULL;
    char       ext[65];
    int        ret = 0;

    if (!mgmt || !file) return "application/octet-stream";

    p = str_trim(file); pend = p + strlen(p);

    poct = rskipTo(pend-1, pend-p, ".", 1);
    if (poct < p) return "application/octet-stream";

    str_secpy(ext, sizeof(ext)-1, poct, pend - poct);

    ret = mime_type_get_by_extname(mgmt->appmime, ext, &p, mimeid, NULL);
    if (ret < 0 || !p || strlen(p) < 1) {
        mime_type_get_by_extname(mgmt->mimemgmt, ext, &p, mimeid, NULL);
    }

    return p;
}

int http_conf_mime_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    void     * mimeobj = NULL;
    char       key[64];
    char     * plist[8];
    int        plen[8];
    int        i, num, j, ret;

    char     * mime;
    int        mimelen;
    char     * ext;
    int        extlen;
    uint32     mimeid;
    uint32     appid;

    if (!mgmt) return -1;

    if (mgmt->appmime == NULL)
        mgmt->appmime = mime_type_alloc(500);

    sprintf(key, "http.mime types");
    json_mget_value(mgmt->cnfjson, key, strlen(key), NULL, NULL, &mimeobj);
    if (!mimeobj) return -100;

    num = json_num(mimeobj);
    for (i = 0; i < num; i++) {
        json_iter(mimeobj, i, 0, (void **)&mime, &mimelen, (void **)&ext, &extlen, NULL);
        if (!mime || mimelen <= 0 || !ext || extlen <= 0)
            continue;

        ret = string_tokenize(ext, extlen, " \t,", 3, (void **)plist, plen, 8);
        for (j = 0; j < ret; j++) {
            if (plist[j] == NULL || plen[j] <= 0)
                continue;

            str_secpy(key, sizeof(key)-1, plist[j], plen[j]);
            mime_type_get_by_mime(mgmt->mimemgmt, mime, NULL, &mimeid, &appid);
            mime_type_add(mgmt->appmime, mime, key, mimeid, appid);
        }
    }

    tolog(1, "eJet - MIME type resource allocated.\n");
    return 0;
}

int http_conf_mime_clean (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    if (mgmt->appmime) {
        mime_type_free(mgmt->appmime);
        mgmt->appmime = NULL;
    }
    
    tolog(1, "eJet - MIME type resource freed.\n");
    return 0;
}

