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

#ifndef _HTTP_SNDPXY_H_
#define _HTTP_SNDPXY_H_

#ifdef UNIX
#include <regex.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
#define PCRE_STATIC 1
#include "pcre.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cli_send_proxy_s {
    char      * host;
#ifdef UNIX
    regex_t   * preg;
#endif
#if defined(_WIN32) || defined(_WIN64)
    pcre      * preg;
#endif

    char      * proxy;
    int         port;
} SendProxy;

int   http_send_proxy_init (void * vmgmt);
void  http_send_proxy_clean (void * vmgmt);

int   http_send_proxy_check (void * vmsg);

#ifdef __cplusplus
}
#endif


#endif

