/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
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

int http_srv_init(void * vsrv);
int http_srv_free (void * vsrv);
int http_srv_recycle (void * vsrv);
void * http_srv_fetch (void * vmgmt);


int http_srv_cmp_srvid (void * a, void * pat)
{    
    HTTPSrv * psrv = (HTTPSrv *)a; 
    ulong     cid = *(ulong *)pat;
     
    if (!psrv || !pat) return -1; 
     
    if (psrv->srvid == cid) return 0; 
    if (psrv->srvid > cid) return 1; 
    return -1;
}    
         
ulong http_srv_hash_func (void * key) 
{        
    ulong cid = *(ulong *)key;
    return cid;
}

int http_mgmt_srv_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    mgmt->srvid = 1;

    InitializeCriticalSection(&mgmt->srvCS);
    mgmt->srv_tree = rbtree_new(http_srv_cmp_srvid, 1);

    if (!mgmt->srv_pool) {  
        mgmt->srv_pool = bpool_init(NULL);
        bpool_set_initfunc (mgmt->srv_pool, http_srv_init);
        bpool_set_freefunc (mgmt->srv_pool, http_srv_free);
        bpool_set_unitsize(mgmt->srv_pool, sizeof(HTTPSrv));
        bpool_set_allocnum(mgmt->srv_pool, 16);
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
            http_srv_free(srv);
        }
        rbtree_free(mgmt->srv_tree);
        mgmt->srv_tree = NULL;
    }

    DeleteCriticalSection(&mgmt->srvCS);

    if (mgmt->srv_pool) {
        bpool_clean(mgmt->srv_pool);
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
    rbtree_insert(mgmt->srv_tree, &srv->srvid, srv, NULL);
    LeaveCriticalSection(&mgmt->srvCS);

    return 0;
}

void * http_mgmt_srv_del (void * vmgmt, ulong srvid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;
 
    if (!mgmt) return NULL;
 
    EnterCriticalSection(&mgmt->srvCS);
    srv = rbtree_delete(mgmt->srv_tree, &srvid);
    LeaveCriticalSection(&mgmt->srvCS);
     
    return srv;
}

void * http_mgmt_srv_get (void * vmgmt, ulong srvid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;
 
    if (!mgmt) return NULL;
 
    EnterCriticalSection(&mgmt->srvCS);
    srv = rbtree_get(mgmt->srv_tree, &srvid);
    LeaveCriticalSection(&mgmt->srvCS);
 
    return srv;
}

void * http_mgmt_srv_find (void * vmgmt, char * ip, int port)
{
    HTTPMgmt  * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv   * iter = NULL;
    rbtnode_t * rbtn = NULL;
    int         i, num;
 
    if (!mgmt) return NULL;
 
    EnterCriticalSection(&mgmt->srvCS);

    num = rbtree_num(mgmt->srv_tree);
    rbtn = rbtree_min_node(mgmt->srv_tree);

    for (i = 0; i < num && rbtn; i++) {
        iter = (HTTPSrv *)RBTObj(rbtn);
        rbtn = rbtnode_next(rbtn);
        if (!iter) continue;

        if (strcasecmp(iter->ip, ip) == 0 && iter->port == port) {
            LeaveCriticalSection(&mgmt->srvCS);
            return iter;
        }
    }

    LeaveCriticalSection(&mgmt->srvCS);
 
    return NULL;
}



int http_srv_init(void * vsrv)
{
    HTTPSrv * srv = (HTTPSrv *)vsrv;

    if (!srv) return -1;

    srv->srvid = 0;

    memset(srv->ip, 0, sizeof(srv->ip));
    srv->port = 0;

    srv->ssl_link = 0;
    srv->sslctx = NULL;
    srv->sslctx_alloc = 0;

    srv->active = 1;
    srv->active_stamp = time(0);

    InitializeCriticalSection(&srv->msgCS);
    if (!srv->msg_fifo) srv->msg_fifo = ar_fifo_new(4);
    ar_fifo_zero(srv->msg_fifo);

    srv->maxcon = 1;
    InitializeCriticalSection(&srv->conCS);

    if (!srv->con_tree) {
        srv->con_tree = rbtree_new(http_con_cmp_conid, 1);
    }
    rbtree_zero(srv->con_tree);

    if (srv->life_timer) {
        iotimer_stop(srv->life_timer);
        srv->life_timer = NULL;
    }

    return 0;
}


int http_srv_free (void * vsrv)
{
    HTTPSrv   * srv = (HTTPSrv *)vsrv;
    /*rbtnode_t * rbtn = NULL;
    HTTPCon   * pcon = NULL;
    int         i, num;*/
 
    if (!srv) return -1;

    if (srv->life_timer) {
        iotimer_stop(srv->life_timer);
        srv->life_timer = NULL;
    }

    DeleteCriticalSection(&srv->conCS);

    rbtree_free(srv->con_tree);

    /* note: http_con_close should recycle the HTTPMsg instance to srv->msg_fifo */

    DeleteCriticalSection(&srv->msgCS);
    ar_fifo_free(srv->msg_fifo);

#ifdef HAVE_OPENSSL
    if (srv->sslctx) {
        if (srv->sslctx_alloc)
            http_ssl_ctx_free(srv->sslctx);
        srv->sslctx = NULL;
        srv->sslctx_alloc = 0;
    }
#endif

    kfree(srv);

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
        return http_srv_free(srv);

    if (srv->life_timer) {
        iotimer_stop(srv->life_timer);
        srv->life_timer = NULL;
    }

    /*num = ht_num(srv->con_table);
    for (i = 0; i < num; i++) {
        http_con_close(ht_value(srv->con_table, i));
    }
    ht_zero(srv->con_table);*/

    num = rbtree_num(srv->con_tree);
    rbtn = rbtree_min_node(srv->con_tree);

    for (i = 0; i < num && rbtn; i++) {
        pcon = RBTObj(rbtn);
        rbtn = rbtnode_next(rbtn);
        http_con_close(pcon);
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

    bpool_recycle(mgmt->srv_pool, srv);

    return 0;
}

void * http_srv_fetch (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;
 
    if (!mgmt) return NULL;

    srv = bpool_fetch(mgmt->srv_pool);
    if (!srv) {
        srv = kzalloc(sizeof(*srv));
        http_srv_init(srv);
    }
    if (!srv) return NULL;

    srv->mgmt = mgmt;

    EnterCriticalSection(&mgmt->srvCS);
    srv->srvid = mgmt->srvid++;
    LeaveCriticalSection(&mgmt->srvCS);

    http_mgmt_srv_add(mgmt, srv);

    return srv;
}

 
void * http_srv_open (void * vmgmt, char * ip, int port, int ssl_link, int maxcon)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPSrv  * srv = NULL;
    uint8      newalloc = 0;

    if (!mgmt) return NULL;

    srv = http_mgmt_srv_find(mgmt, ip, port);
    if (!srv) {
        srv = http_srv_fetch(mgmt);
        if (!srv) return NULL;

        newalloc = 1;

        strncpy(srv->ip, ip, sizeof(srv->ip)-1);
        srv->port = port;
    }

    srv->ssl_link = ssl_link;
    if (srv->ssl_link) {
#ifdef HAVE_OPENSSL
        if (mgmt->srv_sslctx) {
            srv->sslctx = mgmt->srv_sslctx;
            srv->sslctx_alloc = 0;
        } else {
            srv->sslctx = http_ssl_client_ctx_init(mgmt->srv_con_cert,
                                mgmt->srv_con_prikey, mgmt->srv_con_cacert);
            srv->sslctx_alloc = 1;
        }
#endif
    }

    srv->maxcon = maxcon;
    if (srv->maxcon < 20) srv->maxcon = 50;

    time(&srv->stamp);

    if (newalloc)
        srv->life_timer = iotimer_start(mgmt->pcore,
                                        mgmt->srv_check_interval * 1000,
                                        t_httpsrv_life,
                                        (void *)srv->srvid,
                                        http_pump, mgmt);

    return srv;
}

int http_srv_close(void * vsrv)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPMgmt * mgmt = NULL;

    if (!srv) return -1;

    mgmt = (HTTPMgmt *)srv->mgmt;

    if (http_mgmt_srv_del(mgmt, srv->srvid) == NULL) return 0;

    return http_srv_recycle(srv);
}
 
void * http_srv_connect (void * vsrv)
{
    HTTPSrv    * srv = (HTTPSrv *)vsrv;
    HTTPCon    * pcon = NULL;
    rbtnode_t  * rbtn = NULL;
    int          connum = 0;
    int          i = 0;
    arr_t      * rmlist = NULL;

    if (!srv) return NULL;

    EnterCriticalSection(&srv->conCS);

    connum = rbtree_num(srv->con_tree);
    rbtn = rbtree_min_node(srv->con_tree);

    for (i = 0; i < connum && rbtn; i++) {
        pcon = RBTObj(rbtn);
        rbtn = rbtnode_next(rbtn);
 
        if ( !pcon || pcon->transact || pcon->httptunnel ||
             pcon->snd_state == HTTP_CON_FEEDING ||
             arr_num(pcon->msg_list) > 0)
            continue;
 
        if (!tcp_connected(iodev_fd(pcon->pdev))) {
            if (!rmlist) rmlist = arr_new(4);
            arr_push(rmlist, pcon);
            continue;

        } else {
            LeaveCriticalSection(&srv->conCS);

            if (rmlist) arr_pop_free(rmlist, http_con_close);

            return pcon;
        }
    }

    LeaveCriticalSection(&srv->conCS);
 
    if (rmlist) arr_pop_free(rmlist, http_con_close);

    return http_con_open(srv, NULL, 0, 0);
}


int http_srv_msg_send (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HTTPCon    * pcon = NULL;
    HTTPSrv    * srv = NULL;
 
    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;
 
    srv = http_srv_open(mgmt, msg->dstip, msg->dstport, msg->ssl_link, 100);
    if (!srv) return -100;
 
    pcon = http_srv_connect(srv);
    if (pcon) {
        /* all R/W events of pcon will delivered to given thread.
           for the Read/Write pipeline of 2 HTTP connections */
        if (msg->workerid > 0)
            iodev_workerid_set(pcon->pdev, msg->workerid);

        http_con_msg_add(pcon, msg);
 
        http_srv_send(pcon);
 
    } else {
        http_srv_msg_push(srv, msg);
    }
 
    return 0;
}


int http_srv_msg_dns_cb (void * vmsg, char * name, int len, void * cache, int status)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
 
    if (status == DNS_ERR_IPV4 || status == DNS_ERR_IPV6) {
        str_secpy(msg->dstip, sizeof(msg->dstip)-1, name, len);
 
    } else if (dns_cache_getip(cache, 0, msg->dstip, sizeof(msg->dstip)-1) <= 0) {
        msg->res_status = 450;
        http_con_msg_del(msg->pcon, msg);
        http_msg_close(msg);
        return -100;
    }
 
    if (http_srv_msg_send(msg) < 0) {
        msg->res_status = 451;
        http_con_msg_del(msg->pcon, msg);
        http_msg_close(msg);
        return -200;
    }

    return 0;
}
 
int http_srv_msg_dns (void * vmsg, void * cb)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    DnsCB    * dnscb = (DnsCB *)cb;
    HTTPMgmt * mgmt = NULL;
    int        ret;
 
    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;
 
    if (!dnscb) dnscb = http_srv_msg_dns_cb;

    if (msg->proxy && msg->proxyport > 0) {
        ret = dns_query(mgmt->pcore, msg->proxy, -1, dnscb, msg);
    } else {
        ret = dns_query(mgmt->pcore, msg->req_host, msg->req_hostlen, dnscb, msg);
    }
 
    return ret;
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


int http_srv_con_add (void * vsrv, void * vpcon)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPCon  * pcon = (HTTPCon *)vpcon;

    if (!srv) return -1;
    if (!pcon) return -2;

    EnterCriticalSection(&srv->conCS);
    rbtree_insert(srv->con_tree, &pcon->conid, pcon, NULL);
    LeaveCriticalSection(&srv->conCS);

    return 0;
}

void * http_srv_con_del (void * vsrv, ulong conid)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPCon  * pcon = NULL;
     
    if (!srv) return NULL;
     
    EnterCriticalSection(&srv->conCS);
    pcon = rbtree_delete(srv->con_tree, &conid);
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


int http_srv_lifecheck (void * vsrv)
{
    HTTPSrv  * srv = (HTTPSrv *)vsrv;
    HTTPMgmt * mgmt = NULL;
    HTTPMsg  * iter = NULL;
    int        msgnum = 0;
    int        connum = 0;
    int        i = 0, num = 0;
    arr_t    * explist = NULL;
    time_t     curt;

    if (!srv) return -1;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return -2;

    /* srv->stamp should be set timestamp when net-IO occurs, 
     * if Net does not connected, srv->stamp will retain the original value  */

    time(&curt);

    msgnum = http_srv_msg_num(srv);
    connum = http_srv_con_num(srv);

    if ( msgnum == 0 && connum == 0 && 
         curt > srv->stamp &&
         curt - srv->stamp >= 120)
    {
        return http_srv_close(srv);
    }

    EnterCriticalSection(&srv->msgCS);

    num = ar_fifo_num(srv->msg_fifo);
    for (i = 0; i < num; i++) {

        iter = ar_fifo_value(srv->msg_fifo, i);
        if (iter && curt - iter->createtime > 30) {

            if (explist == NULL)
                explist = arr_new(4);

            arr_push(explist, ar_fifo_out(srv->msg_fifo));
            num--; i--;

        } else break;
    }

    LeaveCriticalSection(&srv->msgCS);
 
    num = arr_num(explist);
    for (i = 0; i < num; i++) {
        iter = arr_value(explist, i);
        http_msg_close(iter);
    }
    if (explist) arr_free(explist);

    msgnum = http_srv_msg_num(srv);

    if (connum < msgnum) {
        if (connum <= 10 && msgnum <= 10) {
            num = msgnum;
        } else if (connum <= msgnum/2) {
            num = msgnum/2;
        } else {
            num = msgnum * 2 / 3;
        }

        for (i = connum; i <= num && i <= srv->maxcon; i++) {
            http_srv_connect(srv);
        }
    }

    srv->life_timer = iotimer_start(mgmt->pcore,
                                    mgmt->srv_check_interval * 1000,
                                    t_httpsrv_life,
                                    (void *)srv->srvid,
                                    http_pump, mgmt);

    return 0;
}

