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

#ifndef _HTTP_SRV_H_
#define _HTTP_SRV_H_
 
#ifdef __cplusplus
extern "C" {
#endif
 
#define t_httpsrv_life        2201
 
typedef struct http_srv {
    void             * res[4];

    ulong              srvid;

    char               host[256];
    int                hostlen;
    int                port;
    uint8              ssl_link;

    /* virtual host instance for connection defined in config file ejet.conf */
    void             * phost;

    char               dstip[3][41];
    uint8              ipnum;
    int                dstport;

    void             * sslctx;
    uint8              sslctx_alloc;

    /* value of httptunnel: 
       1 --> accepted HTTPCon from client, that serves as HTTP Tunnel for the client side
       2 --> connected HTTPCon to Origin server, that serves as HTTP Tunnel for the Origin
       3 --> connected HTTPCon to Proxy server, that serves as HTTP Tunnel for self

       Two kinds of HTTPCon, (1) and (2), must be existing in pairs
     */
    uint8              proxied;
    char             * proxyhost;
    int                proxyport;

    int                active; //0-cannot connect to  1-can connect to
    time_t             active_stamp;
 
    CRITICAL_SECTION   msgCS;
    void             * msg_fifo;
 
    int                maxcon;
    CRITICAL_SECTION   conCS;
    //hashtab_t        * con_table;
    rbtree_t         * con_tree;
    rbtree_t           mem_con_tree;

    int                concnt;
    int                rtt;
 
    CRITICAL_SECTION   timesCS;
    int                trytimes;
    int                failtimes;
    int                succtimes;

    time_t             stamp;
    void             * life_timer;
    int                life_times;

    void             * mgmt;
} HTTPSrv;
 

int    http_mgmt_srv_init (void * vmgmt);
int    http_mgmt_srv_clean(void * vmgmt);

int    http_mgmt_srv_add  (void * vmgmt, void * vsrv);
void * http_mgmt_srv_get  (void * vmgmt, ulong srvid);
void * http_mgmt_srv_del  (void * vmgmt, ulong srvid);

int    http_mgmt_hostsrv_add (void * vmgmt, void * vsrv);
void * http_mgmt_hostsrv_del (void * vmgmt, char * host, int hostlen, int port, uint8 ssllink);
void * http_mgmt_hostsrv_get (void * vmgmt, char * host, int hostlen, int port, uint8 ssllink);

void * http_srv_open (void * vmgmt, char * host, int hostlen, int port, int ssllink);
int    http_srv_close(void * vmgmt, ulong srvid);
 
int    http_srv_con_add (void * vsrv, ulong conid);
void * http_srv_con_del (void * vsrv, ulong conid);
int    http_srv_con_num (void * vsrv);
void * http_srv_con_fetch (void * vsrv, ulong workerid);
int    http_srv_con_open (void * vsrv, void * vmsg);


int    http_srv_msg_dns_cb (void * vmgmt, ulong msgid, char * name, int len, void * cache, int status);
int    http_srv_msg_dns    (void * vsrv, void * vmsg, void * cb);
int    http_srv_msg_send   (void * vmsg);

void * http_srv_ssl_ctx_get (void * vsrv, void * vcon);

int    http_srv_set_active (void * vsrv, int active);
int    http_srv_get_active (void * vsrv, time_t * lasttick);


int    http_srv_msg_push (void * vsrv, void * vmsg);
void * http_srv_msg_pull (void * vsrv);
int    http_srv_msg_num (void * vsrv);
int    http_srv_msg_exist (void * vsrv, void * msg);

 
int    http_srv_confail_times (void * vsrv, int times);
int    http_srv_consucc_times (void * vsrv, int times);
int    http_srv_concnt_add    (void * vsrv, int times);

int    http_srv_lifecheck (void * vmgmt, ulong srvid);
 
#ifdef __cplusplus
}
#endif
 
#endif

