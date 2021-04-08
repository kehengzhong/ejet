/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_PROXY_H_
#define _HTTP_PROXY_H_

#ifdef __cplusplus
extern "C" {
#endif

int    http_proxy_handle (void * vmsg);
 
int    http_proxy_check (void * vmsg, void * purl, int urlen);
 
int    http_proxy_srv_send_start (void * vproxymsg);
int    http_proxy_srvmsg_dns_cb  (void * vproxymsg, char * name, int len, void * cache, int status);

void * http_proxy_srvmsg_open (void * vmsg, char * url, int urllen);
int    http_proxy_srv_send    (void * vsrvcon, void * vsrvmsg);

int    http_proxy_climsg_dup (void * vsrvmsg);
int    http_proxy_cli_send   (void * vclicon, void * vclimsg);

int    http_proxy_srvbody_del (void * vsrvcon, void * vsrvmsg);


void * http_proxy_connect_tunnel (void * vcon, void * vmsg);
int    http_tunnel_srv_send (void * vclicon, void * vsrvcon);
int    http_tunnel_cli_send (void * vsrvcon, void * vclicon);


int    http_proxy_climsg_header (void * vclimsg);
int    http_proxy_cli_cache_send (void * vclicon, void * vclimsg);
int    http_proxy_srv_cache_store(void * vclicon, void * vclimsg);
void * http_proxy_srv_cache_send (void * vmsg);

#ifdef __cplusplus
}
#endif

#endif


