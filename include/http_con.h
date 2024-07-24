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

#ifndef _HTTP_CON_H_
#define _HTTP_CON_H_

#include "http_resloc.h"
#include "http_msg.h"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* timer command id that identify the timeout event type */
#define t_http_srv_con_build   2120
#define t_http_cli_con_life    2121
#define t_http_srv_con_life    2122


/* HTTP connection automation state definition for HTTP Receiving (Request or Response) */
#define HTTP_CON_NULL                0
#define HTTP_CON_READY               1
#define HTTP_CON_TUNNEL_BUILDING     2
#define HTTP_CON_SSL_HANDSHAKING     3
#define HTTP_CON_RECVING             4
#define HTTP_CON_WAITING_HEADER      5
#define HTTP_CON_WAITING_BODY        6

/* HTTP connection automation state definition for HTTP Sending (Request or Response) */
#define HTTP_CON_IDLE                0
#define HTTP_CON_CONNECTING          10
#define HTTP_CON_SEND_READY          11
#define HTTP_CON_FEEDING             12

#define HTTP_TUNNEL_NONE             0
#define HTTP_TUNNEL_DNSING           1
#define HTTP_TUNNEL_CONING           2
#define HTTP_TUNNEL_FAIL             3
#define HTTP_TUNNEL_SUCC             4


typedef struct http_con {
    void             * res[4];

    void             * kmemblk;
    uint16             alloctype : 8;
    uint16             casetype  : 8;

    ulong              conid;
    ulong              workerid;

    unsigned           rcv_state      : 10;
    unsigned           snd_state      : 10;
    unsigned           tunnel_built   : 6;
    unsigned           tunnel_state   : 6;

    /* for accepting client-request case, srcip is client-side ip and 
       dstip is server ip itself.
       for sending http-request by connecting to origin, dstip is origin server ip. */
    char               srcip[41];
    int                srcport;
    char               dstip[41];
    int                dstport;

    HTTPListen       * hl;

    /* reading or writing data by following socket communication facilities */
    CRITICAL_SECTION   rcvCS;
    CRITICAL_SECTION   excCS;
    void             * pdev;
    ulong              devid;
#ifdef HAVE_OPENSSL
    SSL_CTX          * sslctx;
    SSL              * ssl;
#endif
    struct http_con  * tunnelcon;
    ulong              tunnelconid;
    char             * tunnelhost;

    frame_p            rcvstream;

    void             * ready_timer;

    time_t             stamp;
    time_t             createtime;
    time_t             transbgn;
    void             * life_timer;

    int                read_ignored;

    unsigned           retrytimes     : 4;
    unsigned           reqnum         : 10;
    unsigned           resnum         : 10;
    unsigned           keepalive      : 1;

    unsigned           ssl_link       : 1;
    unsigned           ssl_handshaked : 1;

    /* sending request and receiving response is named as one transaction.
       pcon's transact flag is a state if it's in processing of sending or receiving.
       0-idle  1-sending request or waiting response */
    unsigned           transact       : 1;

    /* value of httptunnel: 
       1 --> accepted HTTPCon from client, that serves as HTTP Tunnel for the client side
       2 --> connected HTTPCon to Origin server, that serves as HTTP Tunnel for the Origin
       3 --> connected HTTPCon to Proxy server, that serves as HTTP Tunnel for self
       Two kinds of HTTPCon, (1) and (2), must be existing in pairs
     */
    unsigned           httptunnel     : 2;
    unsigned           tunnelself     : 1;

    /* client request HTTPMsg instance */
    HTTPMsg          * msg;

    /* multiple requests occur over single tcp connection, response
     * should be pipelined to reply to client */
    arr_t            * msg_list;
    CRITICAL_SECTION   msglistCS;

    uint64             total_recv;
    uint64             total_sent;

    /* system management instance */
    void             * pcore;
    void             * mgmt;
    void             * srv;

} HTTPCon;



int http_con_cmp_http_con(void * a, void * b);
int http_con_cmp_conid   (void * a, void * pat);

ulong http_con_hash_func (void * key);

/* http connection instance release/initialize/recycle routines */
int    http_con_init (void * vcon);
int    http_con_free (void * vcon);
int http_mgmt_con_free (void * vcon);

#define http_con_recycle(vcon) http_con_recycle_dbg((vcon), __FILE__, __LINE__)
int    http_con_recycle_dbg (void * vcon, char * file, int line);

void * http_con_fetch   (void * vmgmt);

void * http_con_open    (void * vsrv, char * dstip, int dstport, int ssl_link, ulong workerid);

#define http_con_close(vmgmt, conid) http_con_close_dbg((vmgmt), (conid), __FILE__, __LINE__)
int    http_con_close_dbg   (void * vmgmt, ulong conid, char * file, int line);

int    http_con_connect   (void * vmgmt, ulong conid);
int    http_con_connected (void * vpcon);

int    http_con_tunnel_build (void * vcon);

char * http_con_srcip (void * vcon);
int    http_con_srcport (void * vcon);
int    http_con_reqnum  (void * vcon);
ulong  http_con_id      (void * vcon);
void * http_con_iodev   (void * vcon);


int    http_con_msg_prepend (void * vcon, void * vmsg);
int    http_con_msg_num   (void * vcon);
int    http_con_msg_add   (void * vcon, void * vmsg);
int    http_con_msg_del   (void * vcon, void * vmsg);
void * http_con_msg_first (void * vcon);
void * http_con_msg_last  (void * vcon);
int    http_con_msg_exist (void * vcon, void * vmsg);


#ifdef __cplusplus
}
#endif

#endif

