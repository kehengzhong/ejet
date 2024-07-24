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

#ifndef _HTTP_LOG_H_
#define _HTTP_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct http_log_ {

    /* log config info */
    uint8              enable;        /* get from conf */
    uint8              proxyenable;  /* get from conf */
    uint8              tunnelenable;  /* get from conf */
    char             * logfile;       /* get from conf */

    KemPool          * wlog_mpool;
    arfifo_t         * logrec_fifo;

    arfifo_t         * wlog_fifo;
    uint8              quit;
    uint8              eventwait;
    uint64             wlog_num;
    void             * wlog_event;

    /* allocated space for log conent of HTTPMsg */
    frame_p            format;

    FILE             * fp;

    void             * mgmt;
} HTTPLog, http_log_t;

void * http_log_init  (void * vmgmt);
int    http_log_clean (void * vlog);

int    http_log_write (void * vmsg);
int    http_con_log_write (void * vcon);

#ifdef __cplusplus
}
#endif

#endif


