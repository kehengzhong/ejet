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

#ifndef _HTTP_SRV_IO_H_
#define _HTTP_SRV_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

int http_srv_con_crash (void * vmgmt, ulong conid, int closelad);

int http_srv_send_probe (void * vmgmt, ulong conid);
int http_srv_send       (void * vmgmt, ulong conid);
int http_srv_send_final (void * vmsg);

int http_srv_recv (void * vmgmt, ulong conid);

int http_srv_recv_parse (void * vcon);
int http_srv_resbody_parse  (void * vcon, void * vmsg, int64 * offset, int64 * savedbytes);

int http_srv_con_lifecheck (void * vmgmt, ulong conid);

#ifdef __cplusplus
}
#endif

#endif


