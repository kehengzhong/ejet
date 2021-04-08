/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_CON_H_
#define _HTTP_CON_H_

#include "http_listen.h"
#include "http_msg.h"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* HTTP Method Constants Definition */
#define HTTP_METHOD_NONE       0
#define HTTP_METHOD_CONNECT    1
#define HTTP_METHOD_DELETE     2
#define HTTP_METHOD_GET        3
#define HTTP_METHOD_HEAD       4
#define HTTP_METHOD_VERSION_10 5
#define HTTP_METHOD_VERSION_11 6
#define HTTP_METHOD_OPTIONS    7
#define HTTP_METHOD_POST       8
#define HTTP_METHOD_PUT        9
#define HTTP_METHOD_TRACE      10


/* timer command id that identify the timeout event type */
#define t_http_srv_con_build   2120
#define t_http_cli_con_life    2121
#define t_http_srv_con_life    2122


/* HTTP connection automation state definition for HTTP Receiving (Request or Response) */
#define HTTP_CON_NULL                0
#define HTTP_CON_READY               1
#define HTTP_CON_SSL_HANDSHAKING     2
#define HTTP_CON_RECVING             3
#define HTTP_CON_WAITING_HEADER      4
#define HTTP_CON_WAITING_BODY        5

/* HTTP connection automation state definition for HTTP Sending (Request or Response) */
#define HTTP_CON_IDLE                0
#define HTTP_CON_CONNECTING          10
#define HTTP_CON_SEND_READY          11
#define HTTP_CON_FEEDING             12


typedef struct http_con {
    void             * res[2];

    HTTPListen       * hl;

    uint8              casetype;
    RequestDiag      * reqdiag;
    void             * reqdiagobj;

    ulong              conid;
    int                rcv_state;
    int                snd_state;

    /* for accepting client-request case, srcip is client-side ip and 
       dstip is server ip itself.
       for sending http-request by connecting to origin, dstip is origin server ip. */
    char               srcip[41];
    int                srcport;
    char               dstip[41];
    int                dstport;

    /* reading or writing data by following socket communication facilities */
    CRITICAL_SECTION   rcvCS;
    void             * pdev;
#ifdef HAVE_OPENSSL
    SSL_CTX          * sslctx;
    SSL              * ssl;
#endif
    struct http_con  * tunnelcon;
    ulong              tunnelconid;
    int                read_ignored;

    frame_p            rcvstream;

    void             * ready_timer;

    time_t             stamp;
    time_t             createtime;
    time_t             transbgn;
    void             * life_timer;

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
    unsigned           httptunnel     : 2;
    unsigned           tunnelself     : 1;

    /* client request HTTPMsg instance */
    HTTPMsg          * msg;

    /* multiple requests occur over single tcp connection, response
     * should be pipelined to reply to client */
    arr_t            * msg_list;
    CRITICAL_SECTION   msglistCS;

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

int    http_con_recycle (void * vcon);
void * http_con_fetch   (void * vmgmt);

void * http_con_open    (void * vsrv, char * dstip, int dstport, int ssl_link);
int    http_con_close   (void * vcon);

int    http_con_connect   (void * vpcon);
int    http_con_connected (void * vpcon);

char * http_con_srcip (void * vcon);
int    http_con_srcport (void * vcon);
int    http_con_reqnum  (void * vcon);
ulong  http_con_id      (void * vcon);
void * http_con_iodev   (void * vcon);

int    http_con_msg_add   (void * vcon, void * vmsg);
int    http_con_msg_del   (void * vcon, void * vmsg);
void * http_con_msg_first (void * vcon);
void * http_con_msg_last  (void * vcon);

#ifdef __cplusplus
}
#endif

#endif

