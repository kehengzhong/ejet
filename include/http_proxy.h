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

#ifndef _HTTP_PROXY_H_
#define _HTTP_PROXY_H_

#ifdef __cplusplus
extern "C" {
#endif

int    http_proxy_handle (void * vmsg);

int    http_proxy_check (void * vmsg, void * purl, int urlen);
int    http_proxy_examine (void * vmsg);

void * http_proxy_srvmsg_open (void * vmsg, char * url, int urllen);
int    http_proxy_launch (void * vmsg);

int    http_proxy_srv_send    (void * vsrvcon, void * vsrvmsg);

int    http_proxy_climsg_dup (void * vsrvmsg, void * vclimsg);
int    http_proxy_cli_send   (void * vsrvcon, void * vsrvmsg, void * vclicon, void * vclimsg);

int    http_proxy_srvbody_del (void * vsrvcon, void * vsrvmsg);


void * http_proxy_connect_tunnel (void * vcon, void * vmsg);
int    http_tunnel_srv_send (void * vclicon, void * vsrvcon);
int    http_tunnel_cli_send (void * vsrvcon, void * vclicon);


int    http_proxy_climsg_header (void * vclimsg);
int    http_proxy_cli_cache_send (void * vclicon, void * vclimsg);
int    http_proxy_srv_cache_store(void * vsrvcon, void * vsrvmsg, void * vclicon, void * vclimsg);
void * http_proxy_srv_cache_send (void * vmsg);

#ifdef __cplusplus
}
#endif

#endif


