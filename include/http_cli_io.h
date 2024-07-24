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

#ifndef _HTTP_CLI_IO_H_
#define _HTTP_CLI_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

#define http_cli_con_crash(mgmt, conid, lad) http_cli_con_crash_dbg((mgmt), (conid), (lad), __FILE__, __LINE__)
int http_cli_con_crash_dbg (void * vmgmt, ulong conid, int closelad, char * file, int line);

int http_cli_accept (void * vmgmt, void * listendev);

int http_cli_recv (void * vmgmt, ulong conid);
int http_cli_recv_parse (void * vcon);

int http_reqbody_handle    (void * vmsg);
int http_cli_reqbody_parse (void * vcon, void * vmsg);

int http_cli_send_probe (void * vmgmt, ulong conid);
int http_cli_send       (void * vmgmt, ulong conid);
int http_cli_send_final (void * vmsg);

int http_cli_con_lifecheck (void * vmgmt, ulong conid);


#ifdef __cplusplus
}
#endif

#endif


