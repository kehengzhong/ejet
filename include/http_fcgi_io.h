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

#ifndef _HTTP_FCGI_IO_H_
#define _HTTP_FCGI_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

#define http_fcgicon_crash_handle(srv, conid) http_fcgicon_crash_handle_dbg(srv, conid, __FILE__, __LINE__)
int http_fcgicon_crash_handle_dbg (void * vsrv, ulong conid, char * file, int line);

int    http_fcgi_send_probe (void * vsrv, ulong conid);
int    http_fcgi_send       (void * vsrv, ulong conid);
int    http_fcgi_send_final (void * vmsg);

int    http_fcgi_recv       (void * vsrv, ulong conid);
int    http_fcgi_recv_parse (void * vcon);
int    http_fcgi_recv_forward (void * vsrv, ulong conid);


int    http_fcgi_handle     (void * vmsg);

int    http_fcgi_check      (void * vmsg, void * purl, int urlen);
int    http_fcgi_examine    (void * vmsg);

void * http_fcgi_send_start (void * vfcgisrv, void * vhttpmsg);
int    http_fcgi_launch     (void * vmsg);

int    http_fcgi_srv_send (void * vfcgicon, void * vfcgimsg);

int    http_fcgi_con_lifecheck (void * vsrv, ulong conid);

#ifdef __cplusplus
}
#endif

#endif


