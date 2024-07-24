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

#include "adifall.ext"
#include "epump.h"

#include "http_header.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_srv.h"
#include "http_con.h"
#include "http_resloc.h"
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

#define MAKESTR(n) STR(n)
#define STR(n) #n

#ifdef PKG_VER
char * g_http_version = MAKESTR(PKG_VER);
char * g_http_build = "eJet/"MAKESTR(PKG_VER)" Web Server built "__DATE__" "__TIME__" "
                      "by kehengzhong@hotmail.com";
#else
char * g_http_version = "1.6.8";
char * g_http_build = "eJet/1.6.8 Web Server built "__DATE__" "__TIME__" "
                      "by kehengzhong@hotmail.com";
#endif
char * g_http_author = "Lao Ke <kehengzhong@hotmail.com>";

char * g_buddha = ""
"#####################################################\n"
"#                       _oo0oo_                     #\n"
"#  #####   #           o8888888o                    #\n"
"#      #   #           88\" . \"88                    #\n"
"#  #########           (| -_- |)                    #\n"
"#  #   #               0\\  =  /0                    #\n"
"#  #   #####         ___/`---'\\___                  #\n"
"#                  .' \\\\|     |// '.                #\n"
"#                 / \\\\|||  :  |||// \\               #\n"
"#                / _||||| -:- |||||- \\              #\n"
"#               |   | \\\\\\  -  /// |   |             #\n"
"#               | \\_|  ''\\---/''  |_/ |             #\n"
"#               \\  .-\\__  '-'  ___/-. /             #\n"
"#             ___'. .'  /--.--\\  `. .'___           #\n"
"#          .\"\" '<  `.___\\_<|>_/___.'  >' \"\" .       #\n"
"#         | | :  `- \\`.;`\\ _ /`;.`/ -`  : | |       #\n"
"#         \\  \\ `_.   \\_ __\\ /__ _/   .-` /  /       #\n"
"#     =====`-.____`.___ \\_____/___.-`___.-'=====    #\n"
"#                       `=---='                     #\n"
"#     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   #\n"
"#  Buddha's power blessing, Buddha's light shining  #\n"
"#####################################################\n";
//"#               佛力加持      佛光普照              #\n"

HTTPMgmt * gp_httpmgmt = NULL;

int http_mgmt_get_conf (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    char       key[256];
    int        keylen = 0;
    int        ret = 0;

    char     * pstr = NULL;

    if (!mgmt) return -1;

    mgmt->conn_check_interval = 5;
    mgmt->srv_check_interval = 20;

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

    sprintf(key, "http.connect.max header size");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->srv_max_header_size);
    if (ret <= 0)
        mgmt->srv_max_header_size = 32*1024;

    sprintf(key, "http.connect.connecting timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->srv_connecting_time);
    if (ret <= 0)
        mgmt->srv_connecting_time = 8;

    sprintf(key, "http.connect.keepalive timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->srv_keepalive_time);
    if (ret <= 0)
        mgmt->srv_keepalive_time = 10;

    sprintf(key, "http.connect.connection idle timeout");  keylen = strlen(key);
    ret = json_mget_int(mgmt->cnfjson, key, keylen, &mgmt->srv_conn_idle_time);
    if (ret <= 0)
        mgmt->srv_conn_idle_time = 180;

    /* When seinding request to origin server by HTTPS/SSL connection, current web server
       will served as SSL client. if strict client authentication is required by SSL peer,
       the certificate, private key and CA verifying chain certificates will be provided. */

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

    mgmt->startup_time = time(NULL);
    sprintf(mgmt->uptimestr, "%lu.sysinfo", mgmt->startup_time);

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
    mgmt->con_table = ht_only_new(30000, http_con_cmp_conid);
    ht_set_hash_func(mgmt->con_table, http_con_hash_func);

    InitializeCriticalSection(&mgmt->acceptconCS);
    mgmt->accept_con_num = 0;

    InitializeCriticalSection(&mgmt->issuedconCS);
    mgmt->issued_con_num = 0;

    mgmt->msgid = 0;
    InitializeCriticalSection(&mgmt->msgidCS);
    InitializeCriticalSection(&mgmt->msgtableCS);
    mgmt->msg_table = ht_only_new(30000, http_msg_cmp_msgid);
    ht_set_hash_func(mgmt->msg_table, http_msg_hash_msgid);

    if (!mgmt->msg_kmem_pool) {
        mgmt->msg_kmem_pool = kempool_alloc(4096*1024, 16384);
    }

    if (!mgmt->msgmem_pool) {
        mgmt->msgmem_pool = mpool_alloc(NULL, 0);
        mpool_set_unitsize(mgmt->msgmem_pool, 8192);
        mpool_set_allocnum(mgmt->msgmem_pool, 1024);
    }

    if (!mgmt->con_kmem_pool) {
        mgmt->con_kmem_pool = kempool_alloc(8192*1024, 16384);
    }

    if (!mgmt->con_pool) { 
        mgmt->con_pool = mpool_osalloc();
        mpool_set_allocnum(mgmt->con_pool, 1024);
        mpool_set_unitsize(mgmt->con_pool, sizeof(HTTPCon));
        mpool_set_initfunc (mgmt->con_pool, http_con_init);
        mpool_set_freefunc (mgmt->con_pool, http_con_free);
    }

    if (!mgmt->msg_pool) {
        mgmt->msg_pool = mpool_osalloc();
        mpool_set_freefunc(mgmt->msg_pool, http_msg_free);
        mpool_set_unitsize(mgmt->msg_pool, sizeof(HTTPMsg) - 1 + mgmt->msgextsize);
        mpool_set_allocnum(mgmt->msg_pool, 1024);
    }

    if (!mgmt->header_unit_pool) {
        mgmt->header_unit_pool = mpool_osalloc();
        mpool_set_initfunc(mgmt->header_unit_pool, hunit_init);
        mpool_set_freefunc(mgmt->header_unit_pool, hunit_free);
        mpool_set_unitsize(mgmt->header_unit_pool, sizeof(HeaderUnit));
        mpool_set_allocnum(mgmt->header_unit_pool, 8192);
    }

    if (!mgmt->frame_pool) {
        mgmt->frame_pool = mpool_alloc(NULL, 0);
        mpool_set_initfunc(mgmt->frame_pool, frame_empty);
        mpool_set_freefunc(mgmt->frame_pool, frame_free_inner);
        mpool_set_unitsize(mgmt->frame_pool, sizeof(frame_t));
        mpool_set_allocnum(mgmt->frame_pool, 128);
        mpool_set_usizefunc(mgmt->frame_pool, frame_size);
        mpool_set_freesize(mgmt->frame_pool, 32*1024);
    }

    if (!mgmt->fragmem_kempool) {
        mgmt->fragmem_kempool = kempool_alloc(256*1024, 0);
    }

    if (!mgmt->mimemgmt) {
        mgmt->mimemgmt = mime_type_init();
        mgmt->mimemgmt_alloc = 1;
    }
    http_conf_mime_init(mgmt);

    http_connect_init(mgmt);

    http_cache_info_init(mgmt);

    http_var_init(mgmt);

    http_status_init(mgmt);
    http_mgmt_srv_init(mgmt);

    InitializeCriticalSection(&mgmt->countCS);
    gettimeofday(&mgmt->count_tick, NULL);
    mgmt->total_recv = 0;
    mgmt->total_sent = 0;

    mgmt->countind = 0;
    mgmt->count_time[mgmt->countind] = btime(0);

    mgmt->count_timer = iotimer_start(mgmt->pcore, COUNT_INTERVAL * 1000,
                                      t_http_count, (void *)NULL,
                                      http_pump, mgmt, 0);


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

    http_listen_cleanup(mgmt);

    if (mgmt->mimemgmt && mgmt->mimemgmt_alloc) {
        mime_type_clean(mgmt->mimemgmt);
        mgmt->mimemgmt = NULL;
        mgmt->mimemgmt_alloc = 0;
    }
    http_conf_mime_clean(mgmt);

    DeleteCriticalSection(&mgmt->conCS);
    if (mgmt->con_table) {
        ht_free_all(mgmt->con_table, http_mgmt_con_free);
        mgmt->con_table = NULL;
    }

    DeleteCriticalSection(&mgmt->acceptconCS);
    DeleteCriticalSection(&mgmt->issuedconCS);

    cookie_mgmt_free(mgmt->cookiemgmt);

    http_mgmt_srv_clean(mgmt);
    http_status_cleanup(mgmt);
    http_send_proxy_clean(mgmt);

    DeleteCriticalSection(&mgmt->msgidCS);

    DeleteCriticalSection(&mgmt->msgtableCS);
    ht_free_all(mgmt->msg_table, http_mgmt_msg_free);

    http_mgmt_fcgisrv_clean(mgmt);

    script_parser_clean();

    http_var_free(mgmt);

    http_connect_cleanup(mgmt);

    if (mgmt->con_pool) {
        mpool_free(mgmt->con_pool);
        mgmt->con_pool = NULL;
    }

    if (mgmt->msg_pool) {
        mpool_free(mgmt->msg_pool);
        mgmt->msg_pool = NULL;
    }

    if (mgmt->header_unit_pool) {
        mpool_free(mgmt->header_unit_pool);
        mgmt->header_unit_pool = NULL;
    }

    if (mgmt->frame_pool) {
        mpool_free(mgmt->frame_pool);
        mgmt->frame_pool = NULL;
    }

    if (mgmt->msgmem_pool) {
        mpool_free(mgmt->msgmem_pool);
        mgmt->msgmem_pool = NULL;
    }

    if (mgmt->msg_kmem_pool) {
        kempool_free(mgmt->msg_kmem_pool);
	mgmt->msg_kmem_pool = NULL;
    }

    if (mgmt->conmem_pool) {
        mpool_free(mgmt->conmem_pool);
        mgmt->conmem_pool = NULL;
    }

    if (mgmt->con_kmem_pool) {
        kempool_free(mgmt->con_kmem_pool);
        mgmt->con_kmem_pool = NULL;
    }

    if (mgmt->fragmem_kempool) {
        kempool_free(mgmt->fragmem_kempool);
	mgmt->fragmem_kempool = NULL;
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

    iotimer_stop(mgmt->pcore, mgmt->count_timer);
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
    mgmt->sent_byte[mgmt->countind % CNTNUM] += sent;
    LeaveCriticalSection(&mgmt->countCS);
}
 
void http_overhead_recv (void * vmgmt, long recv)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return;
 
    EnterCriticalSection(&mgmt->countCS);
    mgmt->total_recv += recv;
    mgmt->recv_byte[mgmt->countind % CNTNUM] += recv;
    LeaveCriticalSection(&mgmt->countCS);
}
 
void http_connection_accepted (void * vmgmt, int num)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return;
 
    EnterCriticalSection(&mgmt->countCS);
    mgmt->accept_con[mgmt->countind % CNTNUM] += num;
    LeaveCriticalSection(&mgmt->countCS);
}

void http_connection_issued (void * vmgmt, int num)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return;

    EnterCriticalSection(&mgmt->countCS);
    mgmt->issued_con[mgmt->countind % CNTNUM] += num;
    LeaveCriticalSection(&mgmt->countCS);
}   

void http_count_timeout (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    int        ind = 0;
 
    if (!mgmt) return;

    EnterCriticalSection(&mgmt->countCS);

    ind = mgmt->countind % CNTNUM;
    mgmt->count_interval[ind] = btime(0) - mgmt->count_time[ind];

    mgmt->countind++;
    ind = mgmt->countind % CNTNUM;
    mgmt->count_time[ind] = btime(0);
 
    mgmt->sent_byte[ind] = 0;
    mgmt->recv_byte[ind] = 0;

    mgmt->accept_con[ind] = mgmt->accept_con_num;
    mgmt->issued_con[ind] = mgmt->issued_con_num;

    LeaveCriticalSection(&mgmt->countCS);

    mgmt->count_timer = iotimer_start(mgmt->pcore, COUNT_INTERVAL * 1000,
                                      t_http_count, (void *)NULL,
                                      http_pump, mgmt, 0);
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
    ht_set(mgmt->con_table, (void *)pcon->conid, pcon);
    LeaveCriticalSection(&mgmt->conCS);

    return 0;
}

void * http_mgmt_con_get (void * vmgmt, ulong conid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;

    if (!mgmt) return NULL;

    EnterCriticalSection(&mgmt->conCS);
    pcon = ht_get(mgmt->con_table, (void *)conid);
    LeaveCriticalSection(&mgmt->conCS);

    return pcon;
}

void * http_mgmt_con_del (void * vmgmt, ulong conid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;

    if (!mgmt) return NULL;

    EnterCriticalSection(&mgmt->conCS);
    pcon = ht_delete(mgmt->con_table, (void *)conid);
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


int http_mgmt_acceptcon_add (void * vmgmt, void * vcon)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = (HTTPCon *)vcon;

    if (!mgmt) return -1;
    if (!pcon) return -2;

    EnterCriticalSection(&mgmt->acceptconCS);
    mgmt->accept_con_num++;
    LeaveCriticalSection(&mgmt->acceptconCS);

    return 0;
}

void * http_mgmt_acceptcon_del (void * vmgmt, ulong conid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;

    if (!mgmt) return NULL;

    EnterCriticalSection(&mgmt->acceptconCS);
    if (mgmt->accept_con_num > 0)
        mgmt->accept_con_num--;
    LeaveCriticalSection(&mgmt->acceptconCS);

    return pcon;
}

int http_mgmt_issuedcon_add (void * vmgmt, void * vcon)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = (HTTPCon *)vcon;

    if (!mgmt) return -1;
    if (!pcon) return -2;

    EnterCriticalSection(&mgmt->issuedconCS);
    mgmt->issued_con_num++;
    LeaveCriticalSection(&mgmt->issuedconCS);

    return 0;
}

void * http_mgmt_issuedcon_del (void * vmgmt, ulong conid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;

    if (!mgmt) return NULL;

    EnterCriticalSection(&mgmt->issuedconCS);
    if (mgmt->issued_con_num > 0)
        mgmt->issued_con_num--;
    LeaveCriticalSection(&mgmt->issuedconCS);

    return pcon;
}


void * http_msg_fetch (void * vmgmt)
{
    HTTPMgmt         * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg          * msg = NULL;

    if (!mgmt) return NULL;
   
    msg = mpool_fetch(mgmt->msg_pool);
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

    msg->hc = mgmt->connectcfg;

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

extern void * g_kmempool;

int http_print (void * vmgmt, frame_p frm, FILE * fp)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    CookieMgmt * cookiemgmt = NULL;
    HTTPLog    * plog = NULL;
    HTTPListen * hl = NULL;
    rbtnode_t  * rbtn = NULL;
    HTTPSrv    * srv = NULL;
    char         buf[512];
    int          i, num, ind;
    double       dv;
    long         memsize = 0;
    FILE       * fpexe = NULL;

    if (!mgmt) return -1;

    memsize += kempool_size(g_kmempool);
    memsize += mpool_size(mgmt->con_pool);
    memsize += mpool_size(mgmt->msg_pool);
    memsize += mpool_size(mgmt->header_unit_pool);
    memsize += mpool_size(mgmt->msgmem_pool);
    memsize += mpool_size(mgmt->srv_pool);
    memsize += mpool_size(mgmt->fcgisrv_pool);
    memsize += mpool_size(mgmt->fcgicon_pool);
    memsize += mpool_size(mgmt->fcgimsg_pool);
    memsize += mpool_size(mgmt->conmem_pool);
    memsize += kempool_size(mgmt->msg_kmem_pool);
    memsize += kempool_size(mgmt->con_kmem_pool);
    memsize += kempool_size(mgmt->fragmem_kempool);

    cookiemgmt = mgmt->cookiemgmt;
    plog = mgmt->httplog;

    str_datetime(NULL, buf, sizeof(buf)-1, 0);
    if (frm) {
        frame_appendf(frm, "CurrentTime: %s\n", buf);

        str_datetime(&mgmt->startup_time, buf, sizeof(buf)-1, 0);
        num = arr_num(mgmt->listen_list);
        frame_appendf(frm, "\nHTTPModule: %s started, uptime: %ld, HTTPListen: %d\n", buf, time(0)-mgmt->startup_time, num);

        for (i = 0; i < num; i++) {
            hl = arr_value(mgmt->listen_list, i);
            if (!hl) continue;
            frame_appendf(frm, "  Listen Port:%d LocalIP:%s SSL:%d ForwardProxy:%d\n",
                          hl->port, hl->localip, hl->ssl_link, hl->forwardproxy);
        }
        frame_appendf(frm, "  Variables: %d\n", ht_num(mgmt->var_table));
        frame_appendf(frm, "  HTTPCon: %d ConID: %lu  AcceptCon: %lu  IssuedCon: %lu\n",
                      ht_num(mgmt->con_table), mgmt->conid, mgmt->accept_con_num, mgmt->issued_con_num);
        frame_appendf(frm, "  HTTPMsg: %d MsgID: %lu\n", ht_num(mgmt->msg_table), mgmt->msgid);
        frame_appendf(frm, "  FcgiSrv: %d\n", ht_num(mgmt->fcgisrv_table));
        frame_appendf(frm, "  CacInfo: %d\n", ht_num(mgmt->cacinfo_table));
        frame_appendf(frm, "  Cookies: %d Domains: %d\n", arr_num(cookiemgmt->cookie_list), ht_num(cookiemgmt->domain_table));
        frame_appendf(frm, "  Status : %d\n", ht_num(mgmt->status_table));
        frame_appendf(frm, "  SndProxy: %d\n", arr_num(mgmt->sndpxy_list));

        mpool_print(mgmt->con_pool, "ConPool", 2, frm, NULL);
        mpool_print(mgmt->msg_pool, "MsgPool", 2, frm, NULL);
        mpool_print(mgmt->header_unit_pool, "HdrPool", 2, frm, NULL);
        mpool_print(mgmt->srv_pool, "SrvPool", 2, frm, NULL);
        mpool_print(mgmt->frame_pool, "FrmPool", 2, frm, NULL);
        mpool_print(mgmt->fcgisrv_pool, "FcgiSrvPool", 2, frm, NULL);
        mpool_print(mgmt->fcgicon_pool, "FcgiConPool", 2, frm, NULL);
        mpool_print(mgmt->fcgimsg_pool, "FcgiMsgPool", 2, frm, NULL);
        mpool_print(mgmt->msgmem_pool, "MsgMemPool", 2, frm, NULL);
        mpool_print(mgmt->conmem_pool, "ConMemPool", 2, frm, NULL);


        if (g_kmempool) {
            KemPool * memp = (KemPool *)g_kmempool;
            mpool_print(memp->kemunit_pool, "KUnitPool", 2, frm, NULL);
        }

        kempool_print(mgmt->msg_kmem_pool, frm, NULL, 0, 0, 0, "MsgKemPool", 2);
        if (mgmt->msg_kmem_pool) {
            KemPool * memp = (KemPool *)mgmt->msg_kmem_pool;
            mpool_print(memp->kemunit_pool, "KUnitPool", 6, frm, NULL);
        }

        kempool_print(mgmt->con_kmem_pool, frm, NULL, 0, 0, 0, "ConKemPool", 2);
        if (mgmt->con_kmem_pool) {
            KemPool * memp = (KemPool *)mgmt->con_kmem_pool;
            mpool_print(memp->kemunit_pool, "KUnitPool", 6, frm, NULL);
        }

        kempool_print(mgmt->fragmem_kempool, frm, NULL, 0, 0, 0, "FragKemPool", 2);
        if (mgmt->fragmem_kempool) {
            KemPool * memp = (KemPool *)mgmt->fragmem_kempool;
            mpool_print(memp->kemunit_pool, "KUnitPool", 6, frm, NULL);
        }

        frame_appendf(frm, "  HTTPLog info: not-write-num=%d  refifo=%d "
                           "accumulated-lognum=%llu\n",
                      ar_fifo_num(plog->wlog_fifo),
                      ar_fifo_num(plog->logrec_fifo),
                      plog->wlog_num);
        plog = mgmt->httplog;
        if (plog && plog->logrec_fifo) {
            num = ar_fifo_num(plog->logrec_fifo);
            for (i = 0; i < num; i++) {
                frame_appendf(frm, "  %d/%d memsize=%d\n",
                        i, num, *(int*)ar_fifo_value(plog->logrec_fifo, i));
            }
        }
        if (plog && plog->wlog_mpool) {
            KemPool * memp = (KemPool *)plog->wlog_mpool;
            mpool_print(memp->kemunit_pool, "KUnitPool", 6, frm, NULL);
            kempool_print(memp, frm, NULL, 0, 0, 0, "LogKemPool", 2);
        }

        frame_appendf(frm, "\n");

        frame_appendf(frm, "  HTTPSrv: %d SrvID: %lu\n", rbtree_num(mgmt->srv_tree), mgmt->srvid);
        num = rbtree_num(mgmt->srv_tree);
        rbtn = rbtree_min_node(mgmt->srv_tree);
        for (i = 0; i < num && rbtn; i++) {
            srv = RBTObj(rbtn);
            rbtn = rbtnode_next(rbtn);
            if (!srv) continue;
            frame_appendf(frm, "    Srv:%lu %s:%d %s/%d SSL:%d Tunnel:%s:%d Msg:%d Con:%d/%d Try:%d/%d/%d\n", 
                          srv->srvid, srv->host, srv->port, srv->dstip[0], srv->ipnum,
                          srv->ssl_link, srv->proxyhost?srv->proxyhost:"", srv->proxyport,
                          ar_fifo_num(srv->msg_fifo), srv->concnt, rbtree_num(srv->con_tree),
                          srv->trytimes, srv->failtimes, srv->succtimes);
        }
        frame_appendf(frm, "\n");

        num = mgmt->countind + 1 > CNTNUM ? CNTNUM : mgmt->countind + 1;

        frame_appendf(frm, "  Accepted HTTPCon of TimePoint: %d\n   ", mgmt->countind + 1);
        ind = mgmt->countind % CNTNUM;
        for (i = 0; i < num; i++) {
            if (ind < i) ind += CNTNUM;
            frame_appendf(frm, " %d", mgmt->accept_con[ind - i]);
            if (i > 0 && (i+1) % 20 == 0) {
                frame_appendf(frm, "\n   ");
            }
        }
        frame_appendf(frm, "\n");

        frame_appendf(frm, "  Initiated HTTPCon of TimePoint: %d\n   ", mgmt->countind + 1);
        ind = mgmt->countind % CNTNUM;
        for (i = 0; i < num; i++) {
            if (ind < i) ind += CNTNUM;
            frame_appendf(frm, " %d", mgmt->issued_con[ind - i]);
            if (i > 0 && (i+1) % 20 == 0) {
                frame_appendf(frm, "\n   ");
            }
        }
        frame_appendf(frm, "\n");

        frame_appendf(frm, "  Recv/Sent Data Amount of TimePoint: %d (Mbps)\n   ", mgmt->countind + 1);
        ind = mgmt->countind % CNTNUM;
        for (i = 0; i < num; i++) {
            if (ind < i) ind += CNTNUM;
            dv = mgmt->recv_byte[ind - i] + mgmt->sent_byte[ind  - i];
            frame_appendf(frm, " %.2f", dv / 1024. / 1024. / COUNT_INTERVAL * 8);
            if (i > 0 && (i+1) % 20 == 0) {
                frame_appendf(frm, "\n   ");
            }
        }
        frame_appendf(frm, "\n");

        frame_appendf(frm, "\nHTTP Total Memory: %ld (B)\n", memsize);
        frame_appendf(frm, "\n");

#if defined(_WIN32) || defined(_WIN64)
#else
        sprintf(buf, "top -b -n1 | grep %u", getpid());
        frame_appendf(frm, "%s\n", buf);
        fpexe = popen(buf, "r");
        if (!fpexe && errno != 0) {
            frame_append(frm, strerror(errno));
        }
        while (fpexe && !feof(fpexe)) {
            memset(buf, 0, sizeof(buf));
            fgets(buf, sizeof(buf)-1, fpexe);
            frame_appendf(frm, "%s", buf);
        }
        if (fpexe) pclose(fpexe);
        frame_appendf(frm, "\n");
#endif

    }

    if (fp) {
        fprintf(fp, "CurrentTime: %s\n", buf);

        str_datetime(&mgmt->startup_time, buf, sizeof(buf)-1, 0);
        num = arr_num(mgmt->listen_list);
        fprintf(fp, "\nHTTPModule: %s started, uptime: %ld, HTTPListen: %d\n", buf, time(0)-mgmt->startup_time, num);
        for (i = 0; i < num; i++) {
            hl = arr_value(mgmt->listen_list, i);
            if (!hl) continue;
            fprintf(fp, "  Listen Port:%d LocalIP:%s SSL:%d ForwardProxy:%d\n",
                    hl->port, hl->localip, hl->ssl_link, hl->forwardproxy);
        }
        fprintf(fp, "  Variables: %d\n", ht_num(mgmt->var_table));
        fprintf(fp, "  HTTPCon: %d ConID: %lu  AcceptCon: %lu  IssuedCon: %lu\n",
                ht_num(mgmt->con_table), mgmt->conid, mgmt->accept_con_num, mgmt->issued_con_num);
        fprintf(fp, "  HTTPMsg: %d MsgID: %lu\n", ht_num(mgmt->msg_table), mgmt->msgid);
        fprintf(fp, "  FcgiSrv: %d\n", ht_num(mgmt->fcgisrv_table));
        fprintf(fp, "  CacInfo: %d\n", ht_num(mgmt->cacinfo_table));
        fprintf(fp, "  Cookies: %d Domains: %d\n", arr_num(cookiemgmt->cookie_list), ht_num(cookiemgmt->domain_table));
        fprintf(fp, "  Status : %d\n", ht_num(mgmt->status_table));
        fprintf(fp, "  SndProxy: %d\n", arr_num(mgmt->sndpxy_list));

        mpool_print(mgmt->con_pool, "ConPool", 2, NULL, fp);
        mpool_print(mgmt->msg_pool, "MsgPool", 2, NULL, fp);
        mpool_print(mgmt->header_unit_pool, "HdrPool", 2, NULL, fp);
        mpool_print(mgmt->srv_pool, "SrvPool", 2, NULL, fp);
        mpool_print(mgmt->frame_pool, "FrmPool", 2, NULL, fp);
        mpool_print(mgmt->fcgisrv_pool, "FcgiSrvPool", 2, NULL, fp);
        mpool_print(mgmt->fcgicon_pool, "FcgiConPool", 2, NULL, fp);
        mpool_print(mgmt->fcgimsg_pool, "FcgiMsgPool", 2, NULL, fp);
        mpool_print(mgmt->msgmem_pool, "MsgMemPool", 2, NULL, fp);
        mpool_print(mgmt->conmem_pool, "ConMemPool", 2, NULL, fp);

        fprintf(fp, "\n");

        if (g_kmempool) {
            KemPool * memp = (KemPool *)g_kmempool;
            mpool_print(memp->kemunit_pool, "KUnitPool", 2, NULL, fp);
        }

        kempool_print(mgmt->msg_kmem_pool, NULL, fp, 0, 0, 0, "MsgKemPool", 2);
        if (mgmt->msg_kmem_pool) {
            KemPool * memp = (KemPool *)mgmt->msg_kmem_pool;
            mpool_print(memp->kemunit_pool, "KUnitPool", 6, NULL, fp);
        }

        kempool_print(mgmt->con_kmem_pool, NULL, fp, 0, 0, 0, "ConKemPool", 2);
        if (mgmt->con_kmem_pool) {
            KemPool * memp = (KemPool *)mgmt->con_kmem_pool;
            mpool_print(memp->kemunit_pool, "KUnitPool", 6, NULL, fp);
        }

        if (mgmt->fragmem_kempool) {
            KemPool * memp = (KemPool *)mgmt->fragmem_kempool;
            kempool_print(memp, NULL, fp, 0, 0, 0, "FragKemPool", 2);
            mpool_print(memp->kemunit_pool, "KUnitPool", 6, NULL, fp);
        }

        fprintf(fp, "  HTTPLog info: not-write-num=%d  refifo=%d "
                           "accumulated-lognum=%llu\n",
                      ar_fifo_num(plog->wlog_fifo),
                      ar_fifo_num(plog->logrec_fifo),
                      plog->wlog_num);
        plog = mgmt->httplog;
        if (plog && plog->logrec_fifo) {
            num = ar_fifo_num(plog->logrec_fifo);
            for (i = 0; i < num; i++) {
                fprintf(fp, "  %d/%d memsize=%d\n",
                        i, num, *(int*)ar_fifo_value(plog->logrec_fifo, i));
            }
        }
        if (plog && plog->wlog_mpool) {
            KemPool * memp = (KemPool *)plog->wlog_mpool;
            kempool_print(memp, NULL, fp, 0, 0, 0, "LogKemPool", 2);
            mpool_print(memp->kemunit_pool, "KUnitPool", 6, fp, NULL);
        }

        frame_appendf(frm, "\n");

        fprintf(fp, "  HTTPSrv: %d SrvID: %lu\n", rbtree_num(mgmt->srv_tree), mgmt->srvid);
        num = rbtree_num(mgmt->srv_tree);
        rbtn = rbtree_min_node(mgmt->srv_tree);
        for (i = 0; i < num && rbtn; i++) {
            srv = RBTObj(rbtn);
            rbtn = rbtnode_next(rbtn);
            if (!srv) continue;
            fprintf(fp, "    Srv:%lu %s:%d %s/%d SSL:%d Tunnel:%s:%d Msg:%d Con:%d/%d Try:%d/%d/%d\n", 
                          srv->srvid, srv->host, srv->port, srv->dstip[0], srv->ipnum,
                          srv->ssl_link, srv->proxyhost?srv->proxyhost:"", srv->proxyport,
                          ar_fifo_num(srv->msg_fifo), srv->concnt, rbtree_num(srv->con_tree),
                          srv->trytimes, srv->failtimes, srv->succtimes);
        }
        fprintf(fp, "\n");

        num = mgmt->countind + 1 > CNTNUM ? CNTNUM : mgmt->countind + 1;

        fprintf(fp, "  Accepted HTTPCon of TimePoint: %d\n   ", mgmt->countind + 1);
        ind = mgmt->countind % CNTNUM;
        for (i = 0; i < num; i++) {
            if (ind < i) ind += CNTNUM;
            fprintf(fp, " %d", mgmt->accept_con[ind - i]);
            if (i > 0 && (i+1) % 20 == 0) {
                fprintf(fp, "\n   ");
            }
        }
        fprintf(fp, "\n");

        fprintf(fp, "  Initiated HTTPCon of TimePoint: %d\n   ", mgmt->countind + 1);
        ind = mgmt->countind % CNTNUM;
        for (i = 0; i < num; i++) {
            if (ind < i) ind += CNTNUM;
            fprintf(fp, " %d", mgmt->issued_con[ind - i]);
            if (i > 0 && (i+1) % 20 == 0) {
                fprintf(fp, "\n   ");
            }
        }
        fprintf(fp, "\n");

        fprintf(fp, "  Recv/Sent Data Amount of TimePoint: %d (Mbps)\n   ", mgmt->countind + 1);
        ind = mgmt->countind % CNTNUM;
        for (i = 0; i < num; i++) {
            if (ind < i) ind += CNTNUM;
            dv = mgmt->recv_byte[ind - i] + mgmt->sent_byte[ind  - i];
            fprintf(fp, " %.2f", dv / 1024. / 1024. / COUNT_INTERVAL * 8);
            if (i > 0 && (i+1) % 20 == 0) {
                fprintf(fp, "\n   ");
            }
        }
        fprintf(fp, "\n");

        fprintf(fp, "\nHTTP Total Memory: %ld (B)\n", memsize);
        fprintf(fp, "\n");


#if defined(_WIN32) || defined(_WIN64)
#else
        sprintf(buf, "top -b -n1 | grep %u", getpid());
        fprintf(fp, "%s\n", buf);
        fpexe = popen(buf, "r");
        if (!fpexe && errno != 0) {
            fprintf(fp, strerror(errno));
        }
        while (fpexe && !feof(fpexe)) {
            memset(buf, 0, sizeof(buf));
            fgets(buf, sizeof(buf)-1, fpexe);
            fprintf(fp, "%s", buf);
        }
        if (fpexe) pclose(fpexe);
        fprintf(fp, "\n");
#endif

    }

    return 0;
}

