/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_SRV_H_
#define _HTTP_SRV_H_
 
#ifdef __cplusplus
extern "C" {
#endif
 
#define t_httpsrv_life        2201
 
typedef struct http_srv {
    void             * res[4];

    ulong              srvid;

    char               ip[41];
    int                port;

    uint8              ssl_link;
    void             * sslctx;
    uint8              sslctx_alloc;

    int                active; //0-cannot connect to  1-can connect to
    time_t             active_stamp;
 
    CRITICAL_SECTION   msgCS;
    void             * msg_fifo;
 
    int                maxcon;
    CRITICAL_SECTION   conCS;
    hashtab_t        * con_table;
    rbtree_t         * con_tree;
 
    time_t             stamp;
    void             * life_timer;

    void             * mgmt;
} HTTPSrv;
 

int    http_mgmt_srv_init (void * vmgmt);
int    http_mgmt_srv_clean(void * vmgmt);

int    http_mgmt_srv_add  (void * vmgmt, void * vsrv);
void * http_mgmt_srv_get  (void * vmgmt, ulong srvid);
void * http_mgmt_srv_del  (void * vmgmt, ulong srvid);
void * http_mgmt_srv_find (void * vmgmt, char * ip, int port);


void * http_srv_open (void * vmgmt, char * ip, int port, int ssl_link, int maxcon);
int    http_srv_close(void * vsrv);
 
void * http_srv_connect (void * vsrv);

int    http_srv_msg_send   (void * vmsg);
int    http_srv_msg_dns_cb (void * vmsg, char * name, int len, void * cache, int status);
int    http_srv_msg_dns    (void * vmsg, void * cb);

void * http_srv_ssl_ctx_get (void * vsrv, void * vcon);

int    http_srv_set_active (void * vsrv, int active);
int    http_srv_get_active (void * vsrv, time_t * lasttick);


int    http_srv_msg_push (void * vsrv, void * vmsg);
void * http_srv_msg_pull (void * vsrv);
int    http_srv_msg_num (void * vsrv);

int    http_srv_con_add (void * vsrv, void * vpcon);
void * http_srv_con_del (void * vsrv, ulong conid);
int    http_srv_con_num (void * vsrv);
 
int    http_srv_lifecheck (void * vsrv);
 
#ifdef __cplusplus
}
#endif
 
#endif

