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

#ifndef _HTTP_FCGI_CON_H_
#define _HTTP_FCGI_CON_H_

#include "http_fcgi_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* timer command id that identify the timeout event type */
#define t_fcgi_srv_con_build   2310
#define t_fcgi_srv_con_life    2312


/* HTTP connection automation state definition for FCGI Receiving (Request or Response) */
#define FCGI_CON_NULL                0
#define FCGI_CON_READY               1
#define FCGI_CON_RECVING             3
#define FCGI_CON_WAITING_HEADER      4
#define FCGI_CON_WAITING_BODY        5

/* HTTP connection automation state definition for FCGI Sending (Request or Response) */
#define FCGI_CON_IDLE                0
#define FCGI_CON_CONNECTING          10
#define FCGI_CON_SEND_READY          11
#define FCGI_CON_FEEDING             12


typedef struct http_fcgi_con {
    void             * res[4];

    ulong              conid;
    ulong              workerid;
    int                rcv_state;
    int                snd_state;

    uint8              socktype : 6; //0-TCP 1-Unix Socket
    uint8              alloctype: 2; //0-default kalloc/kfree 1-os-specific malloc/free 2-kmempool alloc/free 3-kmemblk alloc/free 

    void             * kmemblk;
 
    char               unixsock[256];
    char               dstip[41];
    int                dstport;

    /* following members used for accept-client probe-device management */
    CRITICAL_SECTION   rcvCS;
    CRITICAL_SECTION   excCS;
    void             * pdev;
    ulong              devid;
    int                read_ignored;

    frame_p            rcvstream;

    void             * ready_timer;

    time_t             stamp;
    time_t             createtime;
    void             * life_timer;

    unsigned           retrytimes     : 4;
    unsigned           reqnum         : 12;
    unsigned           resnum         : 10;
    unsigned           keepalive      : 1;

    /* current handling FcgiMsg request instance */
    FcgiMsg          * msg;

    /* multiple requests occur over single tcp connection, response
     * should be pipelined to reply to client */
    arr_t            * msg_list;
    CRITICAL_SECTION   msglistCS;


    /* system management instance */
    void             * pcore;
    void             * srv;

} FcgiCon, fcgi_con_t;



int http_fcgicon_cmp_fcgicon (void * a, void * b);
int http_fcgicon_cmp_conid   (void * a, void * pat);

ulong http_fcgicon_hash_func (void * key);

/* http connection instance release/initialize/recycle routines */
int    http_fcgicon_init (void * vcon);
int    http_mgmt_fcgicon_free (void * vcon);
int    http_fcgicon_free (void * vcon);

#define http_fcgicon_recycle(vcon) http_fcgicon_recycle_dbg(vcon, __FILE__, __LINE__)
int    http_fcgicon_recycle_dbg (void * vcon, char * file, int line);
void * http_fcgicon_fetch   (void * vmgmt);

void * http_fcgicon_open (void * vsrv, ulong workerid);

#define http_fcgicon_close(srv, conid) http_fcgicon_close_dbg(srv, conid, __FILE__, __LINE__)
int    http_fcgicon_close_dbg (void * vsrv, ulong conid, char * file, int line);

int    http_fcgicon_connect   (void * vsrv, ulong conid);
int    http_fcgicon_connected (void * vpcon);

int    http_fcgicon_reqnum  (void * vcon);
ulong  http_fcgicon_id      (void * vcon);
void * http_fcgicon_device  (void * vcon);


int    http_fcgicon_msg_add   (void * vcon, void * vmsg);
int    http_fcgicon_msg_del   (void * vcon, void * vmsg);
void * http_fcgicon_msg_first (void * vcon);
void * http_fcgicon_msg_last  (void * vcon);
int    http_fcgicon_msg_exist (void * vcon, void * vmsg);


#ifdef __cplusplus
}
#endif

#endif

