/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "http_sndpxy.h"
#include "http_mgmt.h"
#include "http_msg.h"


void * send_proxy_alloc ()
{
    SendProxy * sndpxy = NULL;

    sndpxy = kzalloc(sizeof(*sndpxy));
    return sndpxy;
}

void send_proxy_free (void * vsndpxy)
{
    SendProxy * sndpxy = (SendProxy *)vsndpxy;

    if (!sndpxy) return;

    if (sndpxy->host)
        kfree(sndpxy->host);

    if (sndpxy->preg) {
#ifdef UNIX
        regfree(sndpxy->preg);
        kfree(sndpxy->preg);
#endif
#if defined(_WIN32) || defined(_WIN64)
        pcre_free(sndpxy->preg);
#endif
    }

    if (sndpxy->proxy)
        kfree(sndpxy->proxy);

    kfree(sndpxy);
}

/* next proxy host and port when sending http request *  / 
 * proxy setting = {
 *     / *# left-side is regular express to request host:port, right-side is proxy host and port * /
 *     ^(.+)sina.com.cn$ = 114.247.94.45:8080;
 * };
 */

int http_send_proxy_init (void * vmgmt)
{
    HTTPMgmt  * mgmt = (HTTPMgmt *)vmgmt;
    void      * jsndpxy = NULL;
    int         ret = 0;
    int         i, num = 0;
    SendProxy * sndpxy = NULL;
    char      * key;
    int         keylen = 0;
    char      * data;
    int         datalen = 0;
    char      * plist[4];
    int         plen[4];

    if (!mgmt) return -1;

    if (mgmt->sndpxy_list == NULL)
        mgmt->sndpxy_list = arr_new(4);

    ret = json_mget_obj(mgmt->cnfjson, "http.send request.proxy setting", -1, &jsndpxy);
    if (ret <= 0) return 0;

    num = json_num(jsndpxy);
    for (i = 0; i < num; i++) {
        ret = json_iter(jsndpxy, i, 0, (void **)&key, &keylen, (void **)&data, &datalen, NULL);
        if (ret <= 0) continue;
        if (!key || keylen <= 0) continue;
        if (!data || datalen <= 0) continue;

        sndpxy = send_proxy_alloc();
        if (!sndpxy) continue;

        sndpxy->host = str_dup(key, keylen);

#ifdef UNIX
        sndpxy->preg = kzalloc(sizeof(regex_t));
        regcomp(sndpxy->preg, sndpxy->host, REG_EXTENDED | REG_ICASE);
#endif
#if defined(_WIN32) || defined(_WIN64)
        sndpxy->preg = pcre_compile(sndpxy->host, PCRE_CASELESS, &key, &keylen, NULL);
#endif

        ret = string_tokenize(data, datalen, ":", 1, (void **)plist, plen, 4);
        if (ret <= 0) {
            send_proxy_free(sndpxy);
            continue;
        }

        sndpxy->proxy = str_dup(plist[0], plen[0]);
        if (ret > 1) {
            sndpxy->port = str_to_int(plist[1], plen[1], 10, NULL);
        }

        arr_push(mgmt->sndpxy_list, sndpxy);
    }

    tolog(1, "eJet - %d Proxy Setting loaded for host-specific http request.\n", num);

    return i;
}

void  http_send_proxy_clean (void * vmgmt)
{
    HTTPMgmt  * mgmt = (HTTPMgmt *)vmgmt;

    if (!mgmt) return;

    if (mgmt->sndpxy_list) {
        arr_pop_free(mgmt->sndpxy_list, send_proxy_free);
        mgmt->sndpxy_list = NULL;
    }

    tolog(1, "eJet - Proxy Setting for host-specific http request cleaned.\n");
}

int http_send_proxy_check (void * vmsg)
{
    HTTPMsg   * msg = (HTTPMsg *)vmsg;
    HTTPMgmt  * mgmt = NULL;
    SendProxy * sndpxy = NULL;
    char        buf[256];
    int         i, num;
    int         ret = 0;
#ifdef UNIX
    regmatch_t  pmat[16];
#endif
#if defined(_WIN32) || defined(_WIN64)
    int         ovec[36];
#endif

    if (!msg) return -1;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;

    str_secpy(buf, sizeof(buf)-1, msg->req_host, msg->req_hostlen);

    if (!msg->ssl_link && msg->req_port != 80) {
        sprintf(buf + strlen(buf), ":%d", msg->req_port);
 
    } else if (msg->ssl_link && msg->req_port != 443) {
        sprintf(buf + strlen(buf), ":%d", msg->req_port);
    }

    num = arr_num(mgmt->sndpxy_list);
    for (i = 0; i < num; i++) {
        sndpxy = arr_value(mgmt->sndpxy_list, i);
        if (!sndpxy) continue;

#ifdef UNIX
        ret = regexec(sndpxy->preg, buf, 16, pmat, 0);
        if (ret == 0) {
#endif
#if defined(_WIN32) || defined(_WIN64)
        ret = pcre_exec(sndpxy->preg, NULL, buf, strlen(buf), 0, 0, ovec, 36);
        if (ret > 0) {
#endif
            msg->proxy = sndpxy->proxy;

            if (sndpxy->port == 0) {
                msg->proxyport = msg->ssl_link ? 443 : 80;
            } else {
                msg->proxyport = sndpxy->port;
            }

            msg->dstport = msg->proxyport;

            return 1;
        }
    }

    return 0;
}

