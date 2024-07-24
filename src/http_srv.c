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

#include "http_mgmt.h"
#include "http_msg.h"
#include "http_con.h"
#include "http_pump.h"
#include "http_srv.h"
#include "http_srv_io.h"
#include "http_ssl.h"
#include "http_fcgi_io.h"
#include "http_cli_io.h"
#include "http_handle.h"
#include "http_proxy.h"


int http_srv_init(void * vsrv);
int http_mgmt_srv_free (void * vsrv);
int http_srv_free (void * vsrv);
int http_srv_recycle (void * vsrv);
void * http_srv_fetch (void * vmgmt);

extern HTTPMgmt * gp_httpmgmt;

typedef struct SrvHost_st {
    char  * host;
    int     hostlen;
    int     port;
    uint8   ssl_link;
} SrvHost;


int http_srv_cmp_srvid (void * a, void * pat)
{    
    HTTPSrv * psrv = (HTTPSrv *)a; 
    ulong     cid = (ulong)pat;
     
    if (!psrv || !pat) return -1; 
     
    if (psrv->srvid == cid) return 0; 
    if (psrv->srvid > cid) return 1; 
    return -1;
}    
         
ulong http_srv_hash_func (void * key) 
{        
    ulong cid = (ulong)key;
    return cid;
}

int http_srv_cmp_srvhost (void * a, void * pat)
{
    HTTPSrv * psrv = (HTTPSrv *)a;
    SrvHost * host = (SrvHost *)pat;
    int       ret = 0;

    if (!psrv || !pat) return -1;

    if (psrv->ssl_link > host->ssl_link) return 1;
    if (psrv->ssl_link < host->ssl_link) return -1;

    if (psrv->port > host->port) return 1;
    if (psrv->port < host->port) return -1;

    if (host->host == NULL || host->hostlen == 0) {
        if (psrv->hostlen == 0) return 0;
        else return 1;
    }

    if (psrv->hostlen == host->hostlen) {
        return str_ncasecmp(psrv->host, host->host, psrv->hostlen);
    } else if (psrv->hostlen > host->hostlen) {
        ret = str_ncasecmp(psrv->host, host->host, host->hostlen);
        if (ret == 0) return 1;
        return ret;
    }

    ret = str_ncasecmp(psrv->host, host->host, psrv->hostlen);
    if (ret == 0) return -1;
    return ret;
}

ulong http_srv_host_hash (void * key)
{
    SrvHost * host = (SrvHost *)key;
    ulong hash = 0;
    char extstr[16];

    if (!host) return 0;

    sprintf(extstr, "%d%d", host->port, host->ssl_link);

    hash = string_hash(extstr, strlen(extstr), 3875791L);
    hash = string_hash(host->host, host->hostlen, hash);

    return hash;
}


int http_mgmt_srv_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    mgmt->srvid = 1;

    InitializeCriticalSection(&mgmt->srvCS);
    mgmt->srv_tree = rbtree_new(http_srv_cmp_srvid, 0);
    mgmt->srv_table = ht_only_new(5000, http_srv_cmp_srvhost);
    ht_set_hash_func(mgmt->srv_table, http_srv_host_hash);

    if (!mgmt->srv_pool) {  
        mgmt->srv_pool = mpool_alloc();
        mpool_set_initfunc (mgmt->srv_pool, http_srv_init);
        mpool_set_freefunc (mgmt->srv_pool, http_srv_free);
        mpool_set_unitsize(mgmt->srv_pool, sizeof(HTTPSrv));
        mpool_set_allocnum(mgmt->srv_pool, 200);
    }

    tolog(1, "eJet - HTTPSrv table for origin server init.\n");
    return 0;
}

int http_mgmt_srv_clean (void * vmgmt)
{
    HTTPMgmt  * mgmt = (HTTPMgmt *)vmgmt;
    rbtnode_t * rbtn = NULL;
    HTTPSrv   * srv = NULL;
    int         i, num;
 
    if (!mgmt) return -1;
 
    if (mgmt->srv_tree) {
        num = rbtree_num(mgmt->srv_tree);
        rbtn = rbtree_min_node(mgmt->srv_tree);
        for (i = 0; i < num && rbtn; i++) {
            srv = (HTTPSrv *)RBTObj(rbtn);
            rbtn = rbtnode_next(rbtn);
            http_mgmt_srv_free(srv);
        }
        rbtree_free(mgmt->srv_tree);
        mgmt->srv_tree = NULL;
    }

    if (mgmt->srv_table) {
        ht_free(mgmt->srv_table);
        mgmt->srv_table = NULL;
    }

    DeleteCriticalSection(&mgmt->srvCS);

    if (mgmt->srv_pool) {
        mpool_free(mgmt->srv_pool);
        mgmt->srv_pool = NULL;
    }

    tolog(1, "eJet - HTTPSrv table for origin server cleaned.\n");
    return 0;
}



int http_mgmt_srv_add (void * vmgmt, void * vsrv)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
 
    if (!mgmt) return -1;
    if (!srv) return -2;

    EnterCriticalSection(&mgmt->srvCS);
    rbtree_insert(mgmt->srv_tree, (void *)srv->srvid, srv, NULL);
    LeaveCriticalSection(&mgmt->srvCS);

    return 0;
}

void * http_mgmt_srv_del (void * vmgmt, ulong srvid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;
 
    if (!mgmt) return NULL;
 
    EnterCriticalSection(&mgmt->srvCS);
    srv = rbtree_delete(mgmt->srv_tree, (void *)srvid);
    LeaveCriticalSection(&mgmt->srvCS);
     
    return srv;
}

void * http_mgmt_srv_get (void * vmgmt, ulong srvid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;
 
    if (!mgmt) return NULL;
 
    EnterCriticalSection(&mgmt->srvCS);
    srv = rbtree_get(mgmt->srv_tree, (void *)srvid);
    LeaveCriticalSection(&mgmt->srvCS);
 
    return srv;
}

int http_mgmt_hostsrv_add (void * vmgmt, void * vsrv)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    SrvHost    hostkey = {0};
    int        ret = 0;
 
    if (!mgmt) return -1;
    if (!srv) return -2;
 
    hostkey.host = srv->host;
    hostkey.hostlen = srv->hostlen;
    hostkey.port = srv->port;
    hostkey.ssl_link = srv->ssl_link;

    EnterCriticalSection(&mgmt->srvCS);
    ret = ht_set(mgmt->srv_table, &hostkey, srv);
    LeaveCriticalSection(&mgmt->srvCS);
 
    return ret;
}

void * http_mgmt_hostsrv_del (void * vmgmt, char * host, int hostlen, int port, uint8 ssllink)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;
    SrvHost    hostkey = {0};
 
    if (!mgmt) return NULL;
 
    hostkey.host = host;
    hostkey.hostlen = hostlen;
    hostkey.port = port;
    hostkey.ssl_link = ssllink;

    EnterCriticalSection(&mgmt->srvCS);
    srv = ht_delete(mgmt->srv_table, &hostkey);
    LeaveCriticalSection(&mgmt->srvCS);
 
    return srv;
}

void * http_mgmt_hostsrv_get (void * vmgmt, char * host, int hostlen, int port, uint8 ssllink)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;
    SrvHost    hostkey = {0};

    if (!mgmt) return NULL;

    hostkey.host = host;
    hostkey.hostlen = hostlen;
    hostkey.port = port;
    hostkey.ssl_link = ssllink;

    EnterCriticalSection(&mgmt->srvCS);
    srv = ht_get(mgmt->srv_table, &hostkey);
    LeaveCriticalSection(&mgmt->srvCS);

    return srv;
}


int http_srv_init(void * vsrv)
{
    HTTPSrv * srv = (HTTPSrv *)vsrv;
    HTTPMgmt * mgmt = NULL;

    if (!srv) return -1;

    mgmt = (HTTPMgmt *)gp_httpmgmt;
    if (!mgmt) return -2;

    srv->res[0] = srv->res[1] = srv->res[2] = srv->res[3] = NULL;

    srv->srvid = 0;

    memset(srv->host, 0, sizeof(srv->host));
    srv->hostlen = 0;
    srv->port = 0;
    srv->ssl_link = 0;

    srv->phost = NULL;

    memset(srv->dstip, 0, sizeof(srv->dstip));
    srv->ipnum = 0;
    srv->dstport = 0;

    srv->sslctx = NULL;
    srv->sslctx_alloc = 0;

    srv->proxied = 0;
    srv->proxyhost = NULL;
    srv->proxyport = 0;

    srv->active = 1;
    srv->active_stamp = time(0);

    InitializeCriticalSection(&srv->msgCS);
    if (!srv->msg_fifo) srv->msg_fifo = ar_fifo_new(4);
    ar_fifo_zero(srv->msg_fifo);

    srv->maxcon = 1;
    InitializeCriticalSection(&srv->conCS);
    srv->concnt = 0;
    srv->rtt = 0;

    rbtree_init(&srv->mem_con_tree, http_con_cmp_conid, 0/*alloc_node*/, 0, NULL, NULL);
    srv->con_tree = &srv->mem_con_tree;

    InitializeCriticalSection(&srv->timesCS);
    srv->trytimes = 0;
    srv->failtimes = 0;
    srv->succtimes = 0;

    srv->life_times = 0;
    if (srv->life_timer) {
        iotimer_stop(mgmt->pcore, srv->life_timer);
        srv->life_timer = NULL;
    }

    return 0;
}


int http_mgmt_srv_free (void * vsrv)
{
    HTTPSrv   * srv = (HTTPSrv *)vsrv;
    HTTPMgmt * mgmt = NULL;

    if (!srv) return -1;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return -2;
 
    if (srv->life_timer) {
        iotimer_stop(mgmt->pcore, srv->life_timer);
        srv->life_timer = NULL;
    }

    /* Before the eJet system exits, all HTTPCon objects will be released
       through con_table. Only after that will all HTTPSrv be released.
       Therefore, HTTPCon in HTTPSrv does not need to be released twice. */

    DeleteCriticalSection(&srv->conCS);

    if (srv->con_tree) {
        rbtree_free(srv->con_tree);
        srv->con_tree = NULL;
    }

    /* note: http_con_close should recycle the HTTPMsg instance to srv->msg_fifo */

    DeleteCriticalSection(&srv->msgCS);
    if (srv->msg_fifo) {
        while (ar_fifo_num(srv->msg_fifo) > 0)
            http_msg_close(ar_fifo_out(srv->msg_fifo));

        ar_fifo_free(srv->msg_fifo);
        srv->msg_fifo = NULL;
    }

#ifdef HAVE_OPENSSL
    if (srv->sslctx) {
        if (srv->sslctx_alloc)
            http_ssl_ctx_free(srv->sslctx);
        srv->sslctx = NULL;
        srv->sslctx_alloc = 0;
    }
#endif

    DeleteCriticalSection(&srv->timesCS);

    mpool_recycle(mgmt->srv_pool, srv);

    return 0;
}

int http_srv_free (void * vsrv)
{
    HTTPSrv   * srv = (HTTPSrv *)vsrv;
    HTTPMgmt * mgmt = NULL;
    rbtnode_t * rbtn = NULL;
    HTTPCon   * pcon = NULL;
    int         i, num;

    if (!srv) return -1;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return -2;
 
    if (srv->life_timer) {
        iotimer_stop(mgmt->pcore, srv->life_timer);
        srv->life_timer = NULL;
    }

    num = rbtree_num(srv->con_tree);
    rbtn = rbtree_min_node(srv->con_tree);

    for (i = 0; i < num && rbtn; i++) {
        pcon = RBTObj(rbtn);
        rbtn = rbtnode_next(rbtn);

        if (!pcon) continue;
        pcon->srv = NULL;
        http_con_close(mgmt, pcon->conid);
    }

    if (srv->con_tree) {
        rbtree_free(srv->con_tree);
        srv->con_tree = NULL;
    }

    DeleteCriticalSection(&srv->conCS);

    /* note: http_con_close should recycle the HTTPMsg instance to srv->msg_fifo */

    DeleteCriticalSection(&srv->msgCS);
    if (srv->msg_fifo) {
        while (ar_fifo_num(srv->msg_fifo) > 0)
            http_msg_close(ar_fifo_out(srv->msg_fifo));

        ar_fifo_free(srv->msg_fifo);
        srv->msg_fifo = NULL;
    }

#ifdef HAVE_OPENSSL
    if (srv->sslctx) {
        if (srv->sslctx_alloc)
            http_ssl_ctx_free(srv->sslctx);
        srv->sslctx = NULL;
        srv->sslctx_alloc = 0;
    }
#endif

    DeleteCriticalSection(&srv->timesCS);

    return 0;
}

int http_srv_recycle (void * vsrv)
{
    HTTPSrv    * srv = (HTTPSrv *)vsrv;
    HTTPMgmt   * mgmt = NULL;
    HTTPCon    * pcon = NULL;
    rbtnode_t  * rbtn = NULL;
    int          i, num;
 
    if (!srv) return -1;
 
    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt || !mgmt->srv_pool)
        return -2;

    if (srv->life_timer) {
        iotimer_stop(mgmt->pcore, srv->life_timer);
        srv->life_timer = NULL;
    }

    num = rbtree_num(srv->con_tree);
    rbtn = rbtree_min_node(srv->con_tree);

    for (i = 0; i < num && rbtn; i++) {
        pcon = RBTObj(rbtn);
        rbtn = rbtnode_next(rbtn);
        http_con_close(mgmt, pcon->conid);
    }

    rbtree_zero(srv->con_tree);
 
    /* note: http_con_close should recycle the HTTPMsg instance to srv->msg_fifo */

    while (ar_fifo_num(srv->msg_fifo) > 0)
        http_msg_close(ar_fifo_out(srv->msg_fifo));
    ar_fifo_zero(srv->msg_fifo);
 
#ifdef HAVE_OPENSSL
    if (srv->sslctx) {
        if (srv->sslctx_alloc)
            http_ssl_ctx_free(srv->sslctx);
        srv->sslctx = NULL;
        srv->sslctx_alloc = 0;
    }
#endif

    mpool_recycle(mgmt->srv_pool, srv);

    return 0;
}

void * http_srv_fetch (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;
 
    if (!mgmt) return NULL;

    srv = mpool_fetch(mgmt->srv_pool);
    if (!srv) return NULL;

    srv->mgmt = mgmt;

    EnterCriticalSection(&mgmt->srvCS);
    srv->srvid = mgmt->srvid++;
    LeaveCriticalSection(&mgmt->srvCS);

    http_mgmt_srv_add(mgmt, srv);

    return srv;
}

 
void * http_srv_open (void * vmgmt, char * host, int hostlen, int port, int ssllink)
{
    HTTPMgmt    * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv     * srv = NULL;
    uint8         newalloc = 0;
    HTTPConnect * hc = NULL;
    HTTPHost    * phost = NULL;

    if (!mgmt) return NULL;

    srv = http_mgmt_hostsrv_get(mgmt, host, hostlen, port, ssllink);
    if (!srv) {
        srv = http_srv_fetch(mgmt);
        if (!srv) return NULL;

        newalloc = 1;

        str_secpy(srv->host, sizeof(srv->host)-1, host, hostlen);
        srv->hostlen = hostlen;
        srv->port = port;
        srv->ssl_link = ssllink;

        if ((hc = mgmt->connectcfg)) {
            phost = http_connect_host_find(hc, host, hostlen, port);
        }

        srv->ipnum = 0;
        srv->dstip[0][0] = srv->dstip[1][0] = srv->dstip[2][0] = '\0';
        srv->dstport = port;

        if (phost) {
            srv->maxcon = phost->maxcon;
            if (srv->maxcon < 20) srv->maxcon = 50;

            if (phost->proxy && strlen(phost->proxyhost) > 0 && phost->proxyport > 0) {
                srv->proxied = 1;
                srv->proxyhost = phost->proxyhost;
                srv->proxyport = phost->proxyport;
                srv->dstport = phost->proxyport;
            }
        }

        http_mgmt_hostsrv_add(mgmt, srv);
    }

#ifdef HAVE_OPENSSL
    if (srv->ssl_link && !srv->sslctx) {
        if ((phost = srv->phost) && phost->prikey && phost->cacert)
            srv->sslctx = http_ssl_client_ctx_init(phost->cert, phost->prikey, phost->cacert);

        if (!srv->sslctx)
            srv->sslctx = http_ssl_client_ctx_init(NULL, NULL, NULL);

        if (!srv->sslctx && (hc = mgmt->connectcfg) && hc->prikey && hc->cacert)
            srv->sslctx = http_ssl_client_ctx_init(hc->cert, hc->prikey, hc->cacert);

        if (srv->sslctx) srv->sslctx_alloc = 1;
        else srv->sslctx_alloc = 0;
    }
#endif

    time(&srv->stamp);

    if (newalloc)
        srv->life_timer = iotimer_start(mgmt->pcore,
                                        mgmt->srv_check_interval * 1000,
                                        t_httpsrv_life,
                                        (void *)srv->srvid,
                                        http_pump, mgmt, 0);

    return srv;
}

int http_srv_close(void * vmgmt, ulong srvid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;

    if (!mgmt) return -1;

    srv = http_mgmt_srv_del(mgmt, srvid);
    if (!srv) {
        tolog(1, "Panic: http_srv_close, SrvID=%lu not exist\n", srvid);
        return -100;
    }

    http_mgmt_hostsrv_del(mgmt, srv->host, srv->hostlen, srv->port, srv->ssl_link);

    return http_srv_recycle(srv);
}
 

int http_srv_con_add (void * vsrv, ulong conid)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPMgmt * mgmt = NULL;
    HTTPCon  * pcon = NULL;
    int        ret = 0;

    if (!srv) return -1;

    if ((mgmt = srv->mgmt) == NULL) return -2;

    pcon = http_mgmt_con_get(mgmt, conid);
    if (!pcon) return -3;

    EnterCriticalSection(&srv->conCS);
    ret = rbtree_insert(srv->con_tree, (void *)conid, pcon, NULL);
    LeaveCriticalSection(&srv->conCS);

    return ret;
}

void * http_srv_con_del (void * vsrv, ulong conid)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPCon  * pcon = NULL;

    if (!srv) return NULL;

    EnterCriticalSection(&srv->conCS);
    pcon = rbtree_delete(srv->con_tree, (void *)conid);
    LeaveCriticalSection(&srv->conCS);

    return pcon;
}

int http_srv_con_num (void * vsrv)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    int        num = 0;

    if (!srv) return 0;

    EnterCriticalSection(&srv->conCS);
    num = rbtree_num(srv->con_tree);
    LeaveCriticalSection(&srv->conCS);

    return num;
}

void * http_srv_con_fetch (void * vsrv, ulong workerid)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPCon  * pcon = NULL;

    if (!srv) return NULL;

    while (1) {
        EnterCriticalSection(&srv->conCS);
        pcon = rbtree_delete_min(srv->con_tree);
        LeaveCriticalSection(&srv->conCS);

        if (!pcon) return NULL;

        if (!tcp_connected(iodev_fd(pcon->pdev))) continue;

        EnterCriticalSection(&pcon->rcvCS);
        iodev_bind_epump(pcon->pdev, BIND_CURRENT_EPUMP, 0, 1);

        pcon->workerid = workerid > 0 ? workerid : 1;
        iodev_workerid_set(pcon->pdev, workerid);
        LeaveCriticalSection(&pcon->rcvCS);

        iodev_set_poll(pcon->pdev);

        return pcon;
    }

    return NULL;
}

int http_srv_con_open (void * vsrv, void * vmsg)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPCon  * pcon = NULL;
    HTTPMsg  * climsg = NULL;
    int        ret = 0;

    if (!msg) return -1;

    if (msg->proxied == 2 && (climsg = http_msg_mgmt_get(msg->httpmgmt, msg->proxymsgid)) &&
        climsg->req_url_type > 0 &&
        http_listen_check_self(msg->httpmgmt,
                               msg->req_host, msg->req_hostlen,
                               msg->dstip, msg->dstport) > 0)
    {
        tolog(1, "Warning: HTTPSrv[%lu %s:%d] %d-dstip=%s:%d, Msg:%lu %s, "
                 "DstIP is self, fifo_msg_num=%d connum=%d\n",
              srv->srvid, srv->host, srv->port, srv->ipnum, srv->dstip[0], srv->dstport,
              msg->msgid, http_uri_string(msg->uri), ar_fifo_num(srv->msg_fifo), rbtree_num(srv->con_tree));

        /* host is itself, needless to proxy */
        http_msg_close(msg);
        
        climsg->proxied = 0;
        climsg->proxymsg = NULL;
        climsg->proxymsgid = 0;
    
        /* URI of Forward Proxy request is itself, stop proxy handling
           and go on subsequent handling: FastCGI check, Reqeust Body
           Receiving and HTTP message handling */

        if (http_fcgi_handle(climsg) >= 0)
            return 0;

        ret = http_reqbody_handle(climsg);
        if (ret < 0) {
            http_cli_con_crash(msg->httpmgmt, climsg->conid, 0);
            return ret;
        } else if (ret == 0) {
            return 0;
        }

        return http_msg_handle(climsg->pcon, climsg);
    }

    pcon = http_con_open(srv, msg->dstip, msg->dstport, msg->ssl_link, msg->workerid);
    if (pcon) {
        /* all R/W events of pcon will delivered to given thread that iodev_t device of HTTPCon resides.
           for the Read/Write pipeline of 2 HTTP connections */

        http_con_msg_add(pcon, msg);

        if (msg->proxied == 2)
            http_proxy_srv_send(pcon, msg);
        else
            http_srv_send(msg->httpmgmt, pcon->conid);
    } else {
        if (msg->proxied == 2 && (climsg = http_msg_mgmt_get(msg->httpmgmt, msg->proxymsgid)) && !climsg->res_encoded) {
            http_msg_close(msg);

            climsg->SetStatus(climsg, 503, NULL);
            climsg->AsynReply(climsg, 1, 1);
        } else {
            http_msg_close(msg);
        }

        return -100;
    }

    return 0;
}

int http_srv_msg_dns_cb (void * vmgmt, ulong msgid, char * name, int len, void * cache, int status)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg  * msg = NULL;
    HTTPMsg  * climsg = NULL;
    HTTPSrv  * srv = NULL;
    int        ret = 0;
 
    if (!mgmt) return -1;
 
    msg = http_msg_mgmt_get(mgmt, msgid);
    if (!msg) return -2;

    srv = (HTTPSrv *)msg->httpsrv;

    if (msg->workerid != get_threadid()) 
        tolog(1, "DnsCBThriadIDFail: Name[%s] Status:%d Msg[%lu %ldms Proxy:%d SrcIP:%s:%d %s] "
                 "Srv[%s MsgNum:%d MsgExist:%d] "
                 "CurThID:%lu MsgWkerID:%lu\n",
             name, status, msgid, btime_diff_now(&msg->createtime),
             msg->proxied, msg->srcip, msg->srcport, http_uri_string(msg->uri),
             srv->host, http_srv_msg_num(srv), http_srv_msg_exist(srv, msg),
             get_threadid(), msg->workerid);

    if (msg->proxied == 2 && (climsg = http_msg_mgmt_get(mgmt, msg->proxymsgid)) == NULL) {
        tolog(1, "DnsCBCliFail: Name[%s] Status:%d Msg[%lu %ldms Proxy:%d SrcIP:%s:%d %s] "
                 "Srv[%s IPNum=%d MsgNum:%d MsgExist:%d] "
                 "CurThID:%lu MsgWkerID:%lu CliMsgID=%lu closed!\n",
             name, status, msgid, btime_diff_now(&msg->createtime),
             msg->proxied, msg->srcip, msg->srcport, http_uri_string(msg->uri),
             srv->host, srv->ipnum, http_srv_msg_num(srv), http_srv_msg_exist(srv, msg),
             get_threadid(), msg->workerid, msg->proxymsgid);

        http_msg_close(msg);
        return 0;
    }

    if (status == DNS_ERR_IPV4 || status == DNS_ERR_IPV6) {
        str_secpy(msg->dstip, sizeof(msg->dstip)-1, name, len);

        if (srv) {
            str_secpy(srv->dstip[0], sizeof(srv->dstip[0])-1, name, len);
            srv->ipnum = 1;
        }
 
        return http_srv_con_open(srv, msg);

    } else if (cache && status == DNS_ERR_NO_ERROR) {
        if (srv) {
            ret = dns_cache_getiplist(cache, srv->dstip, 3);
            if (ret > 0) {
                str_cpy(msg->dstip, srv->dstip[0]); 
                srv->ipnum = ret;
            }
        } else {
            ret = dns_cache_getip(cache, 0, msg->dstip, sizeof(msg->dstip)-1);
        }

        if (ret > 0) {
            return http_srv_con_open(srv, msg);
        }
    }

    http_srv_confail_times(srv, 1);

    tolog(1, "DnsFail: Name[%s] Status:%d Msg[%lu %ldms Proxy:%d SrcIP:%s:%d %s] "
             "Srv[%s MsgNum:%d MsgExist:%d] "
             "CurThID:%lu MsgWkerID:%lu\n",
             name, status, msgid, btime_diff_now(&msg->createtime),
             msg->proxied, msg->srcip, msg->srcport, http_uri_string(msg->uri),
             srv->host, http_srv_msg_num(srv), http_srv_msg_exist(srv, msg),
             get_threadid(), msg->workerid);

    msg->res_status = 450;
    http_con_msg_del(msg->pcon, msg);

    if (msg->proxied == 2 && (climsg = http_msg_mgmt_get(mgmt, msg->proxymsgid)) && !climsg->res_encoded) {
        http_msg_close(msg);

        climsg->SetStatus(climsg, 503, NULL);
        climsg->AsynReply(climsg, 1, 1);
    } else {
        http_msg_close(msg);
    }

    return -100;
}
 
int http_srv_msg_dns (void * vsrv, void * vmsg, void * cb)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    DnsCB    * dnscb = (DnsCB *)cb;
    HTTPMgmt * mgmt = NULL;
    int        ret;
 
    if (!srv) return -1;
    if (!msg) return -2;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -3;
 
    if (!dnscb) dnscb = http_srv_msg_dns_cb;

    if (srv->proxied && srv->proxyhost) {
        msg->dstport = srv->proxyport;

        ret = dns_query(mgmt->pcore, srv->proxyhost, -1, dnscb, mgmt, msg->msgid);

    } else {
        ret = dns_query(mgmt->pcore, msg->req_host, msg->req_hostlen, dnscb, mgmt, msg->msgid);
    }
 
    return ret;
}

int http_srv_msg_send (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    HTTPCon  * pcon = NULL;
    HTTPSrv  * srv = NULL;
    HTTPMsg  * climsg = NULL;
 
    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;
 
    /* When in proxy mode, eJet can not build SSL connection to middle proxy server */

    msg->httpsrv = srv = http_srv_open(mgmt, msg->req_host, msg->req_hostlen, msg->req_port, msg->ssl_link);
    if (!srv || (srv->trytimes > 16 && srv->failtimes * 100 / srv->trytimes >= 97)) {
        /* if the success ratio of connecting to origin is lower than 3%, close the msg or reply error */
        if (msg->proxied == 2 && (climsg = http_msg_mgmt_get(mgmt, msg->proxymsgid)) && !climsg->res_encoded) {
            http_msg_close(msg);

            climsg->SetStatus(climsg, 503, NULL);
            climsg->AsynReply(climsg, 1, 1);
        } else {
            http_msg_close(msg);
        }
        return -200;
    }

    msg->dstport = srv->dstport;

    if ((pcon = http_srv_con_fetch(srv, msg->workerid)) != NULL) {
        http_con_msg_add(pcon, msg);

        str_cpy(msg->dstip, pcon->dstip);

        if (msg->proxied == 2)
            http_proxy_srv_send(pcon, msg);
        else
            http_srv_send(mgmt, pcon->conid);

        return 0;
    }

    if (srv->ipnum == 0) {
        /* host need to be resolved by DNS */
        return http_srv_msg_dns(srv, msg, http_srv_msg_dns_cb);
    }

    str_cpy(msg->dstip, srv->dstip[0]);

    return http_srv_con_open(srv, msg);
}


void * http_srv_ssl_ctx_get (void * vsrv, void * vcon)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;

    if (!srv) return NULL;

    return srv->sslctx;
}


int http_srv_set_active (void * vsrv, int active)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    int        old = 0;
 
    if (!srv) return 0;
 
    old = srv->active;
    srv->active = active;

    if (old != active) srv->active_stamp = time(0);

    return old;
}

int http_srv_get_active (void * vsrv, time_t * lasttick)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv; 
 
    if (lasttick) *lasttick = 0;

    if (!srv) return 0;
 
    if (lasttick) *lasttick = srv->active_stamp;
    return srv->active;
}
 

int http_srv_msg_push (void * vsrv, void * vmsg)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPMsg  * msg = (HTTPMsg *)vmsg;

    if (!srv) return -1;
    if (!msg) return -2;

    EnterCriticalSection(&srv->msgCS);
    ar_fifo_push(srv->msg_fifo, msg);
    LeaveCriticalSection(&srv->msgCS);

    return 0;
}

void * http_srv_msg_pull (void * vsrv)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPMsg  * msg = NULL;

    if (!srv) return NULL;

    EnterCriticalSection(&srv->msgCS);
    msg = ar_fifo_out(srv->msg_fifo);
    LeaveCriticalSection(&srv->msgCS);

    return msg;
}

int http_srv_msg_num (void * vsrv)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    int        num = 0;
 
    if (!srv) return 0;
 
    EnterCriticalSection(&srv->msgCS);
    num = ar_fifo_num(srv->msg_fifo);
    LeaveCriticalSection(&srv->msgCS);
 
    return num;
}

int http_srv_msg_exist (void * vsrv, void * msg)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    int        i = 0, num = 0;
 
    if (!srv) return -1;
 
    EnterCriticalSection(&srv->msgCS);
    num = ar_fifo_num(srv->msg_fifo);
    for (i = 0; i < num; i++) {
        if (msg == ar_fifo_value(srv->msg_fifo, i))
            break;
    }
    LeaveCriticalSection(&srv->msgCS);
 
    if (i >= num) return -100;
    return i;
}

int http_srv_confail_times (void * vsrv, int times)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;

    if (!srv) return 0;

    EnterCriticalSection(&srv->timesCS);
    srv->trytimes += times;
    srv->failtimes += times;
    LeaveCriticalSection(&srv->timesCS);

    return 1;
}

int http_srv_consucc_times (void * vsrv, int times)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;

    if (!srv) return 0;
 
    EnterCriticalSection(&srv->timesCS);
    srv->trytimes += times;
    srv->failtimes += times - 1;
    srv->succtimes++;
    LeaveCriticalSection(&srv->timesCS);
    
    return 1;
}

int http_srv_concnt_add (void * vsrv, int times)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;

    if (!srv) return 0;
 
    EnterCriticalSection(&srv->conCS);
    srv->concnt += times;
    LeaveCriticalSection(&srv->conCS);
    
    return srv->concnt;
}


int http_srv_lifecheck (void * vmgmt, ulong srvid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;
    HTTPMsg  * iter = NULL;
    int        msgnum = 0;
    int        connum = 0;
    int        i = 0, num = 0;
    arr_t    * explist = NULL;
    time_t     curt;

    if (!mgmt) return -1;

    srv = http_mgmt_srv_get(mgmt, srvid);
    if (!srv) return -2;

    srv->life_times++;

    if (srv->life_times * mgmt->srv_check_interval % 90 < mgmt->srv_check_interval) {
        EnterCriticalSection(&srv->timesCS);
        srv->trytimes = 0;
        srv->failtimes = 0;
        srv->succtimes = 0;
        LeaveCriticalSection(&srv->timesCS);
    }

    /* srv->stamp should be set timestamp when net-IO occurs, 
     * if Net does not connected, srv->stamp will retain the original value  */

    time(&curt);

    msgnum = http_srv_msg_num(srv);
    connum = http_srv_con_num(srv);

    if ( msgnum == 0 && connum == 0 && 
         curt > srv->stamp &&
         curt - srv->stamp >= 120)
    {
        return http_srv_close(mgmt, srvid);
    }

    EnterCriticalSection(&srv->msgCS);

    num = ar_fifo_num(srv->msg_fifo);
    for (i = 0; i < num; i++) {

        iter = ar_fifo_value(srv->msg_fifo, i);
        if (iter && curt - iter->createtime.s > 30) {

            if (explist == NULL)
                explist = arr_new(4);

            arr_push(explist, ar_fifo_out(srv->msg_fifo));
            num--; i--;

        } else break;
    }

    LeaveCriticalSection(&srv->msgCS);
 
    num = arr_num(explist);
    if (num > 0)
        tolog(1, "Warning: HTTPSrv[%lu %s:%d] fifo_msg_num=%d connum=%d expired_msg_num=%d\n",
              srv->srvid, srv->host, srv->port, ar_fifo_num(srv->msg_fifo),
              rbtree_num(srv->con_tree), num);

    for (i = 0; i < num; i++) {
        iter = arr_value(explist, i);
        http_msg_close(iter);
    }
    if (explist) arr_free(explist);

    msgnum = http_srv_msg_num(srv);

    if (connum < msgnum) {
        tolog(1, "Warning: HTTPSrv[%lu %s:%d] fifo_msg_num=%d connum=%d\n",
              srv->srvid, srv->host, srv->port, ar_fifo_num(srv->msg_fifo),
              rbtree_num(srv->con_tree));

        if (connum <= 10 && msgnum <= 10) {
            num = msgnum;
        } else if (connum <= msgnum/2) {
            num = msgnum/2;
        } else {
            num = msgnum * 2 / 3;
        }
    }

    srv->life_timer = iotimer_start(mgmt->pcore,
                                    mgmt->srv_check_interval * 1000,
                                    t_httpsrv_life,
                                    (void *)srvid,
                                    http_pump, mgmt, 0);

    return 0;
}

