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

#ifndef _HTTP_FCGI_SRV_H_
#define _HTTP_FCGI_SRV_H_
 
#ifdef __cplusplus
extern "C" {
#endif
 
#define t_fcgi_srv_life        2201
 
typedef struct http_fcgi_srv {

    /* fpmsrv is UNIX-socket address or domain name of FPM server.
        unix:/dev/shm/php-cgi.sock
        fastcgi://127.0.0.1:9000
     */
    char               cgisrv[256];

    uint8              socktype;   //0-TCP 1-Unix Socket

    char               unixsock[256];

    char               ip[41];
    int                port;

    CRITICAL_SECTION   msgCS;
    uint16             msgid;
    hashtab_t        * msg_table;
    void             * msg_fifo;
 
    int                maxcon;
    CRITICAL_SECTION   conCS;
    ulong              conid;
    rbtree_t         * con_tree;
    rbtree_t           mem_con_tree;
 
    CRITICAL_SECTION   timesCS;
    int                trytimes;
    int                failtimes;
    int                succtimes;

    time_t             stamp;
    void             * life_timer;
    int                life_times;

    void             * mgmt;
    void             * pcore;
} FcgiSrv, fcgi_srv_t;
 

int    http_mgmt_fcgisrv_init (void * vmgmt);
int    http_mgmt_fcgisrv_clean(void * vmgmt);

int    http_mgmt_fcgisrv_add  (void * vmgmt, void * vsrv);
void * http_mgmt_fcgisrv_get  (void * vmgmt, char * cgisrv);
void * http_mgmt_fcgisrv_del  (void * vmgmt, char * cgisrv);


void * http_fcgisrv_open (void * vmgmt, char * cgisrv, int maxcon);
int    http_fcgisrv_close(void * vsrv);
 
uint16 http_fcgisrv_get_msgid (void * vsrv);
ulong  http_fcgisrv_get_conid (void * vsrv);

void * http_fcgisrv_connect (void * vsrv, ulong workerid);

int    http_fcgisrv_msg_add (void * vsrv, void * vmsg);
void * http_fcgisrv_msg_get (void * vsrv, uint16 msgid);
void * http_fcgisrv_msg_del (void * vsrv, uint16 msgid);

int    http_fcgisrv_msg_push (void * vsrv, void * vmsg);
void * http_fcgisrv_msg_pull (void * vsrv);
int    http_fcgisrv_msg_num (void * vsrv);

int    http_fcgisrv_con_add (void * vsrv, void * vpcon);
void * http_fcgisrv_con_get (void * vsrv, ulong conid);
void * http_fcgisrv_con_del (void * vsrv, ulong conid);
int    http_fcgisrv_con_num (void * vsrv);
 
int    http_fcgisrv_confail_times (void * vsrv, int times);
int    http_fcgisrv_consucc_times (void * vsrv, int times);

int    http_fcgisrv_lifecheck (void * vsrv);
 
int    http_fcgisrv_pump (void * vsrv, void * vobj, int event, int fdtype);

#ifdef __cplusplus
}
#endif
 
#endif

