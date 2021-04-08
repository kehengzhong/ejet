/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"

#include "http_mgmt.h"
#include "http_msg.h"
#include "http_fcgi_srv.h"
#include "http_fcgi_con.h"
#include "http_fcgi_msg.h"
#include "http_fcgi_io.h"


int    http_fcgisrv_init    (void * vsrv);
int    http_fcgisrv_free    (void * vsrv);
int    http_fcgisrv_recycle (void * vsrv);
void * http_fcgisrv_fetch   (void * vmgmt);


int http_fcgisrv_cmp_cgisrv (void * a, void * b)
{    
    FcgiSrv * psrv = (FcgiSrv *)a; 
    char    * cgisrv = (char *)b;
     
    if (!psrv || !cgisrv) return -1; 

    return strcasecmp(psrv->cgisrv, cgisrv);
}    


int http_mgmt_fcgisrv_init (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return -1;

    InitializeCriticalSection(&mgmt->fcgisrvCS);
    mgmt->fcgisrv_table = ht_only_new(13, http_fcgisrv_cmp_cgisrv);

    if (!mgmt->fcgisrv_pool) {  
        mgmt->fcgisrv_pool = mpool_alloc();
        mpool_set_initfunc (mgmt->fcgisrv_pool, http_fcgisrv_init);
        mpool_set_freefunc (mgmt->fcgisrv_pool, http_fcgisrv_free);
        mpool_set_unitsize (mgmt->fcgisrv_pool, sizeof(FcgiSrv));
        mpool_set_allocnum (mgmt->fcgisrv_pool, 2);
    }

    if (!mgmt->fcgicon_pool) {  
        mgmt->fcgicon_pool = mpool_alloc();
        mpool_set_initfunc (mgmt->fcgicon_pool, http_fcgicon_init);
        mpool_set_freefunc (mgmt->fcgicon_pool, http_fcgicon_free);
        mpool_set_unitsize (mgmt->fcgicon_pool, sizeof(FcgiCon));
        mpool_set_allocnum (mgmt->fcgicon_pool, 16);
    }

    if (!mgmt->fcgimsg_pool) {  
        mgmt->fcgimsg_pool = mpool_alloc();
        mpool_set_initfunc (mgmt->fcgimsg_pool, http_fcgimsg_init);
        mpool_set_freefunc (mgmt->fcgimsg_pool, http_fcgimsg_free);
        mpool_set_unitsize (mgmt->fcgimsg_pool, sizeof(FcgiMsg));
        mpool_set_allocnum (mgmt->fcgimsg_pool, 32);
    }

    tolog(1, "eJet - FastCGI module (Unix Socket/TCP) init.\n");
    return 0;
}

int http_mgmt_fcgisrv_clean (void * vmgmt)
{
    HTTPMgmt  * mgmt = (HTTPMgmt *)vmgmt;
    FcgiSrv   * srv = NULL;
    int         i, num;
 
    if (!mgmt) return -1;
 
    if (mgmt->fcgisrv_table) {
        num = ht_num(mgmt->fcgisrv_table);
        for (i = 0; i < num; i++) {
            srv = ht_value(mgmt->fcgisrv_table, i);
            http_fcgisrv_free(srv);
        }
        ht_free(mgmt->fcgisrv_table);
        mgmt->fcgisrv_table = NULL;
    }

    DeleteCriticalSection(&mgmt->fcgisrvCS);

    if (mgmt->fcgisrv_pool) {
        mpool_free(mgmt->fcgisrv_pool);
        mgmt->fcgisrv_pool = NULL;
    }

    if (mgmt->fcgicon_pool) {
        mpool_free(mgmt->fcgicon_pool);
        mgmt->fcgicon_pool = NULL;
    }

    if (mgmt->fcgimsg_pool) {
        mpool_free(mgmt->fcgimsg_pool);
        mgmt->fcgimsg_pool = NULL;
    }

    tolog(1, "eJet - FastCGI module (Unix Socket/TCP) cleaned.\n");
    return 0;
}

int http_mgmt_fcgisrv_add (void * vmgmt, void * vsrv)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
 
    if (!mgmt) return -1;
    if (!srv) return -2;

    EnterCriticalSection(&mgmt->srvCS);
    ht_set(mgmt->fcgisrv_table, &srv->cgisrv, srv);
    LeaveCriticalSection(&mgmt->srvCS);

    return 0;
}

void * http_mgmt_fcgisrv_del (void * vmgmt, char * cgisrv)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    FcgiSrv  * srv = NULL;
 
    if (!mgmt) return NULL;
 
    EnterCriticalSection(&mgmt->srvCS);
    srv = ht_delete(mgmt->fcgisrv_table, cgisrv);
    LeaveCriticalSection(&mgmt->srvCS);
     
    return srv;
}

void * http_mgmt_fcgisrv_get (void * vmgmt, char * cgisrv)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    FcgiSrv  * srv = NULL;
 
    if (!mgmt) return NULL;
 
    EnterCriticalSection(&mgmt->srvCS);
    srv = ht_get(mgmt->fcgisrv_table, cgisrv);
    LeaveCriticalSection(&mgmt->srvCS);
 
    return srv;
}


int http_fcgisrv_init (void * vsrv)
{
    FcgiSrv * srv = (FcgiSrv *)vsrv;

    if (!srv) return -1;

    srv->cgisrv[0] = '\0';
    srv->socktype = 0;

    memset(srv->ip, 0, sizeof(srv->ip));
    srv->port = 0;

    InitializeCriticalSection(&srv->msgCS);
    srv->msgid = 1;
    if (!srv->msg_table) {
        srv->msg_table = ht_only_new(300, http_fcgimsg_cmp_msgid);
        ht_set_hash_func(srv->msg_table, http_fcgimsg_hash_msgid);
    }
    ht_zero(srv->msg_table);

    if (!srv->msg_fifo) srv->msg_fifo = ar_fifo_new(4);
    ar_fifo_zero(srv->msg_fifo);

    srv->maxcon = 1;
    InitializeCriticalSection(&srv->conCS);
    srv->conid = 1;

    if (!srv->con_tree) {
        srv->con_tree = rbtree_new(http_fcgicon_cmp_conid, 1);
    }
    rbtree_zero(srv->con_tree);

    if (srv->life_timer) {
        iotimer_stop(srv->life_timer);
        srv->life_timer = NULL;
    }

    return 0;
}


int http_fcgisrv_free (void * vsrv)
{
    FcgiSrv   * srv = (FcgiSrv *)vsrv;
    rbtnode_t * rbtn = NULL;
    FcgiCon   * pcon = NULL;
    FcgiMsg   * msg = NULL;
    int         i, num;
 
    if (!srv) return -1;

    if (srv->life_timer) {
        iotimer_stop(srv->life_timer);
        srv->life_timer = NULL;
    }

    DeleteCriticalSection(&srv->conCS);

    num = rbtree_num(srv->con_tree);
    rbtn = rbtree_min_node(srv->con_tree);

    for (i = 0; i < num && rbtn; i++) {
        pcon = RBTObj(rbtn);
        rbtn = rbtnode_next(rbtn);

        if (!pcon) continue;
        http_fcgicon_close(pcon);
    }

    rbtree_free(srv->con_tree);

    /* note: http_fcgicon_close should recycle the FcgiMsg instance to srv->msg_fifo */

    num = ht_num(srv->msg_table);
    for (i = 0; i < num; i++) {
        msg = ht_value(srv->msg_table, i);
        if (!msg) continue;

        http_fcgimsg_close(msg);
    }
    ht_free(srv->msg_table);

    DeleteCriticalSection(&srv->msgCS);
    ar_fifo_free(srv->msg_fifo);

    return 0;
}

int http_fcgisrv_recycle (void * vsrv)
{
    FcgiSrv    * srv = (FcgiSrv *)vsrv;
    HTTPMgmt   * mgmt = NULL;
    FcgiCon    * pcon = NULL;
    rbtnode_t  * rbtn = NULL;
    int          i, num;
 
    if (!srv) return -1;
 
    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt || !mgmt->fcgisrv_pool)
        return http_fcgisrv_free(srv);

    if (srv->life_timer) {
        iotimer_stop(srv->life_timer);
        srv->life_timer = NULL;
    }

    num = rbtree_num(srv->con_tree);
    rbtn = rbtree_min_node(srv->con_tree);

    for (i = 0; i < num && rbtn; i++) {
        pcon = RBTObj(rbtn);
        rbtn = rbtnode_next(rbtn);
        http_fcgicon_close(pcon);
    }

    rbtree_zero(srv->con_tree);
 
    /* note: http_fcgicon_close should recycle the FcgiMsg instance to srv->msg_fifo */

    while (ar_fifo_num(srv->msg_fifo) > 0)
        http_msg_close(ar_fifo_out(srv->msg_fifo));
    ar_fifo_zero(srv->msg_fifo);
 
    mpool_recycle(mgmt->fcgisrv_pool, srv);

    return 0;
}

void * http_fcgisrv_fetch (void * vmgmt)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    FcgiSrv  * srv = NULL;
 
    if (!mgmt) return NULL;

    srv = mpool_fetch(mgmt->fcgisrv_pool);
    if (!srv) {
        srv = kzalloc(sizeof(*srv));
        http_fcgisrv_init(srv);
    }
    if (!srv) return NULL;

    srv->mgmt = mgmt;
    srv->pcore = mgmt->pcore;

    return srv;
}

static int fcgisrv_parse (FcgiSrv * srv)
{
    char  * pbgn = NULL;
    char  * pend = NULL;
    char  * poct = NULL;

    if (!srv) return -1;

    pbgn = srv->cgisrv;
    pend = pbgn + strlen(pbgn);

    if (strncasecmp(pbgn, "unix:", 5) == 0) {
        srv->socktype = 1;
        str_secpy(srv->unixsock, sizeof(srv->unixsock)-1, pbgn + 5, pend - pbgn - 5);
        return 0;
    }

    if (strncasecmp(pbgn, "fastcgi://", 10) == 0) {
        srv->socktype = 0;

        pbgn += 10;

        poct = skipTo(pbgn, pend - pbgn, ":", 1);
        if (poct > pbgn) {
            str_secpy(srv->ip, sizeof(srv->ip) - 1, pbgn, poct - pbgn);
        }
        if (poct + 1 < pend && *poct == ':') {
            srv->port = strtol(poct + 1, NULL, 10);
        }

        return 0;
    }

    return -2;
}
 
void * http_fcgisrv_open (void * vmgmt, char * cgisrv, int maxcon)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    FcgiSrv  * srv = NULL;
    uint8      newalloc = 0;

    if (!mgmt || !cgisrv) return NULL;

    srv = http_mgmt_fcgisrv_get(mgmt, cgisrv);
    if (!srv) {
        srv = http_fcgisrv_fetch(mgmt);
        if (!srv) return NULL;

        newalloc = 1;

        strncpy(srv->cgisrv, cgisrv, sizeof(srv->cgisrv)-1);
        fcgisrv_parse(srv);

        http_mgmt_fcgisrv_add(mgmt, srv);
    }

    srv->maxcon = maxcon;
    if (srv->maxcon < 20) srv->maxcon = 50;

    time(&srv->stamp);

    if (newalloc)
        srv->life_timer = iotimer_start(mgmt->pcore,
                                        mgmt->srv_check_interval * 1000,
                                        t_fcgi_srv_life,
                                        (void *)srv,
                                        http_fcgisrv_pump, srv);

    return srv;
}

int http_fcgisrv_close(void * vsrv)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    HTTPMgmt * mgmt = NULL;

    if (!srv) return -1;

    mgmt = (HTTPMgmt *)srv->mgmt;

    if (http_mgmt_fcgisrv_del(mgmt, srv->cgisrv) == NULL) return 0;

    return http_fcgisrv_recycle(srv);
}
 
uint16 http_fcgisrv_get_msgid (void * vsrv)
{
    FcgiSrv * srv = (FcgiSrv *)vsrv;
    uint16    msgid = 1;

    if (!srv) return msgid;

    EnterCriticalSection(&srv->conCS);
    if (srv->msgid == 0)
        srv->msgid = 1;
    msgid = srv->msgid++;
    LeaveCriticalSection(&srv->conCS);

    return msgid;
}

ulong http_fcgisrv_get_conid (void * vsrv)
{
    FcgiSrv * srv = (FcgiSrv *)vsrv;
    ulong     conid = 0;
 
    if (!srv) return conid;
 
    EnterCriticalSection(&srv->conCS);
    if (srv->conid == 0)
        srv->conid = 1;
    conid = srv->conid++;
    LeaveCriticalSection(&srv->conCS);
 
    return conid;
}


void * http_fcgisrv_connect (void * vsrv)
{
    FcgiSrv    * srv = (FcgiSrv *)vsrv;
    FcgiCon    * pcon = NULL;
    rbtnode_t  * rbtn = NULL;
    int          connum = 0;
    int          i = 0;

    if (!srv) return NULL;

    EnterCriticalSection(&srv->conCS);

    connum = rbtree_num(srv->con_tree);
    rbtn = rbtree_min_node(srv->con_tree);

    for (i = 0; i < connum && rbtn; i++) {
        pcon = RBTObj(rbtn);
        rbtn = rbtnode_next(rbtn);
 
        if ( !pcon || 
             pcon->snd_state == FCGI_CON_FEEDING ||
             arr_num(pcon->msg_list) > 0)
            continue;
 
        LeaveCriticalSection(&srv->conCS);

        return pcon;
    }

    LeaveCriticalSection(&srv->conCS);
 
    return http_fcgicon_open(srv);
}


int http_fcgisrv_msg_add (void * vsrv, void * vmsg)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiMsg  * msg = (FcgiMsg *)vmsg;
 
    if (!srv) return -1;
    if (!msg) return -2;
 
    EnterCriticalSection(&srv->msgCS);
    ht_set(srv->msg_table, &msg->msgid, msg);
    LeaveCriticalSection(&srv->msgCS);
 
    return 0;
}
 
void * http_fcgisrv_msg_get (void * vsrv, uint16 msgid)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiMsg  * msg = NULL;
 
    if (!srv) return NULL;
 
    EnterCriticalSection(&srv->msgCS);
    msg = ht_get(srv->msg_table, &msgid);
    LeaveCriticalSection(&srv->msgCS);
 
    return msg;
}

void * http_fcgisrv_msg_del (void * vsrv, uint16 msgid)
{    
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiMsg  * msg = NULL;
 
    if (!srv) return NULL;
 
    EnterCriticalSection(&srv->msgCS); 
    msg = ht_delete(srv->msg_table, &msgid);
    LeaveCriticalSection(&srv->msgCS);
     
    return msg;
}    

int http_fcgisrv_msg_push (void * vsrv, void * vmsg)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiMsg  * msg = (FcgiMsg *)vmsg;

    if (!srv) return -1;
    if (!msg) return -2;

    EnterCriticalSection(&srv->msgCS);
    ar_fifo_push(srv->msg_fifo, msg);
    LeaveCriticalSection(&srv->msgCS);

    return 0;
}

void * http_fcgisrv_msg_pull (void * vsrv)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiMsg  * msg = NULL;

    if (!srv) return NULL;

    EnterCriticalSection(&srv->msgCS);
    msg = ar_fifo_out(srv->msg_fifo);
    LeaveCriticalSection(&srv->msgCS);

    return msg;
}

int http_fcgisrv_msg_num (void * vsrv)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    int        num = 0;
 
    if (!srv) return 0;
 
    EnterCriticalSection(&srv->msgCS);
    num = ar_fifo_num(srv->msg_fifo);
    LeaveCriticalSection(&srv->msgCS);
 
    return num;
}


int http_fcgisrv_con_add (void * vsrv, void * vpcon)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = (FcgiCon *)vpcon;

    if (!srv) return -1;
    if (!pcon) return -2;

    EnterCriticalSection(&srv->conCS);
    rbtree_insert(srv->con_tree, &pcon->conid, pcon, NULL);
    LeaveCriticalSection(&srv->conCS);

    return 0;
}

void * http_fcgisrv_con_get (void * vsrv, ulong conid)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = NULL;
     
    if (!srv) return NULL;
     
    EnterCriticalSection(&srv->conCS);
    pcon = rbtree_get(srv->con_tree, &conid);
    LeaveCriticalSection(&srv->conCS);
 
    return pcon;
}

void * http_fcgisrv_con_del (void * vsrv, ulong conid)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = NULL;
     
    if (!srv) return NULL;
     
    EnterCriticalSection(&srv->conCS);
    pcon = rbtree_delete(srv->con_tree, &conid);
    LeaveCriticalSection(&srv->conCS);
 
    return pcon;
}

int http_fcgisrv_con_num (void * vsrv)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    int        num = 0;
 
    if (!srv) return 0;
 
    EnterCriticalSection(&srv->conCS);
    num = rbtree_num(srv->con_tree);
    LeaveCriticalSection(&srv->conCS);
 
    return num;
}


int http_fcgisrv_lifecheck (void * vsrv)
{
    FcgiSrv        * srv = (FcgiSrv *)vsrv;
    HTTPMgmt       * mgmt = NULL;
    FcgiMsg        * iter = NULL;
    int              msgnum = 0;
    int              connum = 0;
    int              i = 0, num = 0;
    arr_t          * explist = NULL;
    time_t           curt;

    if (!srv) return -1;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return -2;

    /* srv->stamp should be set timestamp when net-IO occurs, 
     * if Net does not connected, srv->stamp will retain the original value  */

    time(&curt);

    msgnum = http_fcgisrv_msg_num(srv);
    connum = http_fcgisrv_con_num(srv);

    if ( msgnum == 0 && connum == 0 && 
         curt > srv->stamp &&
         curt - srv->stamp >= mgmt->fcgi_srv_alive_time)
    {
        return http_fcgisrv_close(srv);
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

    msgnum = http_fcgisrv_msg_num(srv);

    if (connum < msgnum) {
        if (connum <= 10 && msgnum <= 10) {
            num = msgnum;
        } else if (connum <= msgnum/2) {
            num = msgnum/2;
        } else {
            num = msgnum * 2 / 3;
        }

        for (i = connum; i <= num && i <= srv->maxcon; i++) {
            http_fcgisrv_connect(srv);
        }
    }

    srv->life_timer = iotimer_start(mgmt->pcore,
                                    mgmt->srv_check_interval * 1000,
                                    t_fcgi_srv_life,
                                    (void *)srv,
                                    http_fcgisrv_pump, srv);

    return 0;
}

int http_fcgisrv_pump (void * vsrv, void * vobj, int event, int fdtype)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = NULL;
    int        cmd = 0;
    ulong      conid = 0;

    if (!srv) return -1;

    switch (event) {
    case IOE_INVALID_DEV:
        conid = (ulong)iodev_para(vobj);
        pcon = http_fcgisrv_con_get(srv, conid);
 
        if (pcon && pcon->pdev == vobj) {
            return http_fcgicon_close(pcon);
        }
        break;

    case IOE_READ:
        conid = (ulong)iodev_para(vobj);
        pcon = http_fcgisrv_con_get(srv, conid);
 
        if (pcon && pcon->pdev == vobj) {
            if (fdtype == FDT_CONNECTED || fdtype == FDT_USOCK_CONNECTED) {
                return http_fcgi_recv(pcon);
 
            } else
                return -1;
 
        } else {
            return -20;
        }
        break;

    case IOE_WRITE:
        conid = (ulong)iodev_para(vobj);
        pcon = http_fcgisrv_con_get(srv, conid);
 
        if (pcon && pcon->pdev == vobj) {
            if (fdtype == FDT_CONNECTED || fdtype == FDT_USOCK_CONNECTED) {
                return http_fcgi_send(pcon);
 
            } else
                return -1;
        } else {
            return -20;
        }
        break;

    case IOE_CONNECTED:
        conid = (ulong)iodev_para(vobj);
        pcon = http_fcgisrv_con_get(srv, conid);
 
        EnterCriticalSection(&pcon->rcvCS);
 
        if (pcon && pcon->pdev == vobj) {
            LeaveCriticalSection(&pcon->rcvCS);

            return http_fcgicon_connected(pcon);
 
        } else {
            LeaveCriticalSection(&pcon->rcvCS);
 
            return -20;
        }
        break;

    case IOE_TIMEOUT:
        cmd = iotimer_cmdid(vobj);

        if (cmd == t_fcgi_srv_life) {
            return http_fcgisrv_lifecheck(srv);

        } else if (cmd == t_fcgi_srv_con_life) {
            conid = (ulong)iotimer_para(vobj);
            pcon = http_fcgisrv_con_get(srv, conid);

            if (pcon && pcon->life_timer == vobj) {
                return http_fcgi_con_lifecheck(pcon);
            }
        }
        break;
    }

    return -1;
}

