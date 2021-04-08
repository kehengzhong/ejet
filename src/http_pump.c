/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"

#include "http_header.h"
#include "http_mgmt.h"
#include "http_msg.h"
#include "http_pump.h"
#include "http_srv.h"
#include "http_con.h"
#include "http_cli_io.h"
#include "http_srv_io.h"
#include "http_handle.h"
#include "http_ssl.h"


int http_pump (void * vmgmt, void * vobj, int event, int fdtype)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon    * pcon = NULL;
    HTTPListen * hl = NULL;
    ulong        conid = 0;
    int          cmd = 0;

    if (!mgmt) return -1;

    switch (event) {
    case IOE_ACCEPT:
        if (fdtype != FDT_LISTEN) 
            return -1;

        hl = (HTTPListen *)http_listen_find(mgmt, iodev_lip(vobj), iodev_lport(vobj));
        if (!hl) return -1;

        return http_cli_accept(mgmt, vobj);

    case IOE_INVALID_DEV:
        conid = (ulong)iodev_para(vobj);
        pcon = http_mgmt_con_get(mgmt, conid);

        if (pcon && pcon->pdev == vobj) {
            tolog(1, "eJet - TCP Connect: invalid connection to '%s:%d'.\n",
                  pcon->dstip, pcon->dstport);

            return http_con_close(pcon);
        }
        break;

    case IOE_READ:
        conid = (ulong)iodev_para(vobj);
        pcon = http_mgmt_con_get(mgmt, conid);

        if (pcon && pcon->pdev == vobj) {

            if (fdtype == FDT_ACCEPTED) {
                if (pcon->ssl_link && !pcon->ssl_handshaked)
                    return http_ssl_accept(pcon);

                else 
                    return http_cli_recv(pcon);

            } else if (fdtype == FDT_CONNECTED) {
                if (pcon->ssl_link && !pcon->ssl_handshaked)
                    return http_ssl_connect(pcon);

                else 
                    return http_srv_recv(pcon);

            } else
                return -1;

        } else {
            return -20;
        }

        break;

    case IOE_WRITE:
        conid = (ulong)iodev_para(vobj);
        pcon = http_mgmt_con_get(mgmt, conid);

        if (pcon && pcon->pdev == vobj) {
            if (fdtype == FDT_ACCEPTED) {
                if (pcon->ssl_link && !pcon->ssl_handshaked)
                    return http_ssl_accept(pcon);

                else 
                    return http_cli_send(pcon);

            } else if (fdtype == FDT_CONNECTED) {
                if (pcon->ssl_link && !pcon->ssl_handshaked)
                    return http_ssl_connect(pcon);

                else 
                    return http_srv_send(pcon);

            } else
                return -1;
        } else {
            return -20;
        }

        break;

    case IOE_TIMEOUT:
        cmd = iotimer_cmdid(vobj);

        if (cmd == t_http_srv_con_life) {
            conid = (ulong)iotimer_para(vobj);
            pcon = http_mgmt_con_get(mgmt, conid);

            if (pcon && pcon->life_timer == vobj) {
                http_srv_con_lifecheck(pcon);
            }

            return 0;

        } else if (cmd == t_http_cli_con_life) {
            conid = (ulong)iotimer_para(vobj);
            pcon = http_mgmt_con_get(mgmt, conid);

            if (pcon && pcon->life_timer == vobj) {
                http_cli_con_lifecheck(pcon);
            }

            return 0;

        } else if (cmd == t_http_srv_con_build) {
            conid = (ulong)iotimer_para(vobj);
            pcon = http_mgmt_con_get(mgmt, conid);

            if (pcon && pcon->ready_timer == vobj) {
                http_con_connect(pcon);
            }

            return 0;

        } else if (cmd == t_httpsrv_life) {
            ulong     srvid = 0;
            HTTPSrv * srv = NULL;

            srvid = (ulong)iotimer_para(vobj);
            srv = http_mgmt_srv_get(mgmt, srvid);

            if (srv && srv->life_timer == vobj) {
                http_srv_lifecheck(srv);
            }

            return 0;
        }
        break;

    case IOE_CONNECTED:
        conid = (ulong)iodev_para(vobj);
        pcon = http_mgmt_con_get(mgmt, conid);

        EnterCriticalSection(&pcon->rcvCS);

        if (pcon && pcon->pdev == vobj) {
            LeaveCriticalSection(&pcon->rcvCS);
            return http_con_connected(pcon);

        } else {
            LeaveCriticalSection(&pcon->rcvCS);

            return -20;
        }
        break;
        
    case IOE_CONNFAIL:
        conid = (ulong)iodev_para(vobj);
        pcon = http_mgmt_con_get(mgmt, conid);

        if (pcon && pcon->pdev == vobj) {
            tolog(1, "eJet - TCP Connect: failed to build connection to '%s:%d'.\n",
                  pcon->dstip, pcon->dstport);
        } else {
            return -20;
        }
        break;
        
    default:
       return -1;
    }

    return -1;
}

void print_pump_arg (void * vobj, int event, int fdtype)
{
#ifdef _DEBUG
    char         buf[256];
 
    buf[0] = '\0';
    sprintf(buf+strlen(buf), "HTTP_Pump: ");
 
    if (event == IOE_CONNECTED)        sprintf(buf+strlen(buf), "IOE_CONNECTED");
    else if (event == IOE_CONNFAIL)    sprintf(buf+strlen(buf), "IOE_CONNFAIL");
    else if (event == IOE_ACCEPT)      sprintf(buf+strlen(buf), "IOE_ACCEPT");
    else if (event == IOE_READ)        sprintf(buf+strlen(buf), "IOE_READ");
    else if (event == IOE_WRITE)       sprintf(buf+strlen(buf), "IOE_WRITE");
    else if (event == IOE_TIMEOUT)     sprintf(buf+strlen(buf), "IOE_TIMEOUT");
    else if (event == IOE_INVALID_DEV) sprintf(buf+strlen(buf), "IOE_INVALID_DEV");
    else                               sprintf(buf+strlen(buf), "Unknown");
 
    if (event != IOE_TIMEOUT) {
        sprintf(buf+strlen(buf), " ");
        if (fdtype == FDT_LISTEN)               sprintf(buf+strlen(buf), "FDT_LISTEN");
        else if (fdtype == FDT_CONNECTED)       sprintf(buf+strlen(buf), "FDT_CONNECTED");
        else if (fdtype == FDT_ACCEPTED)        sprintf(buf+strlen(buf), "FDT_ACCEPTED");
        else if (fdtype == FDT_UDPSRV)          sprintf(buf+strlen(buf), "FDT_UDPSRV");
        else if (fdtype == FDT_UDPCLI)          sprintf(buf+strlen(buf), "FDT_UDPCLI");
        else if (fdtype == FDT_RAWSOCK)         sprintf(buf+strlen(buf), "FDT_RAWSOCK");
        else if (fdtype == FDT_TIMER)           sprintf(buf+strlen(buf), "FDT_TIMER");
        else if (fdtype == FDT_LINGER_CLOSE)    sprintf(buf+strlen(buf), "FDT_LINGER_CLOSE");
        else if (fdtype == FDT_STDIN)           sprintf(buf+strlen(buf), "FDT_STDIN");
        else if (fdtype == FDT_STDOUT)          sprintf(buf+strlen(buf), "FDT_STDOUT");
        else if (fdtype == FDT_USOCK_LISTEN)    sprintf(buf+strlen(buf), "FDT_USOCK_LISTEN");
        else if (fdtype == FDT_USOCK_CONNECTED) sprintf(buf+strlen(buf), "FDT_USOCK_CONNECTED");
        else if (fdtype == FDT_USOCK_ACCEPTED)  sprintf(buf+strlen(buf), "FDT_USOCK_ACCEPTED");
        else                                    sprintf(buf+strlen(buf), "Unknown Type");
 
        sprintf(buf+strlen(buf), " FD=%d R<%s:%d> L<%s:%d>",
                 iodev_fd(vobj), iodev_rip(vobj), iodev_rport(vobj),
                 iodev_lip(vobj), iodev_lport(vobj));
    } else {
        if (vobj) {
            sprintf(buf+strlen(buf), " CmdID=%d ID=%lu WID=%lu",
                    iotimer_cmdid(vobj), iotimer_id(vobj), iotimer_workerid(vobj));
        }
    }
    printf("%s\n", buf);
#endif
}
