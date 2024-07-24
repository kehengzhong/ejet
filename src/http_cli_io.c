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

#include "adifall.ext"
#include "epump.h"
#include "http_con.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_pump.h"
#include "http_cli_io.h"
#include "http_resloc.h"
#include "http_request.h"
#include "http_handle.h"
#include "http_proxy.h"
#include "http_srv.h"
#include "http_chunk.h"
#include "http_ssl.h"
#include "http_variable.h"
#include "http_form.h"
#include "http_cache.h"
#include "http_cc.h"

#include "http_fcgi_srv.h"
#include "http_fcgi_msg.h"
#include "http_fcgi_con.h"
#include "http_fcgi_io.h"


//int http_cli_con_crash (void * vmgmt, ulong conid, int closelad)
int http_cli_con_crash_dbg (void * vmgmt, ulong conid, int closelad, char * file, int line)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * clicon = NULL;
    HTTPMsg  * climsg = NULL;
    HTTPMsg  * srvmsg = NULL;
    HTTPCon  * srvcon = NULL;
    FcgiSrv  * cgisrv = NULL;
    FcgiMsg  * cgimsg = NULL;
    FcgiCon  * cgicon = NULL;

    if (!mgmt) return -1;

    clicon = http_mgmt_con_get(mgmt, conid);
    if (!clicon) return -2;

    climsg = http_con_msg_first(clicon);

    if (closelad && clicon->httptunnel == 1 && clicon->tunnelcon) {
        http_con_close_dbg(mgmt, clicon->tunnelconid, file, line);
    }

    else if (climsg && climsg->proxied == 1 && (srvmsg = http_msg_mgmt_get(mgmt, climsg->proxymsgid))) {
        srvcon = http_mgmt_con_get(mgmt, srvmsg->conid);
        if (srvcon) {
            if (closelad) http_con_close_dbg(mgmt, srvmsg->conid, file, line);
        } else { //srvmsg not yet bound to HTTPCon
            http_msg_close_dbg(srvmsg, file, line);
        }
    }

    else if (climsg && climsg->fastcgi == 1 && (cgimsg = climsg->fcgimsg)) {
        cgisrv = (FcgiSrv *)cgimsg->srv;
        cgicon = http_fcgisrv_con_get(cgisrv, cgimsg->conid);
        if (cgicon) {
            if (closelad) http_fcgicon_close(cgisrv, cgimsg->conid);
        } else
            http_fcgimsg_close(cgimsg);
    }

    return http_con_close_dbg(mgmt, conid, file, line);
}

int http_cli_accept (void * vmgmt, void * listendev)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon    * pcon = NULL;
    int          ret = 0;
    void       * pdev = NULL;
    HTTPListen * hl = NULL;
 
    if (!mgmt) return -1;
 
    hl = iodev_para(listendev);
    if (!hl) return -2;

    while (1) {
        pdev = eptcp_accept(mgmt->pcore, listendev, NULL,
                            (void *)NULL, http_pump, mgmt,
                            BIND_NONE, 0, &ret);
        if (pdev == NULL) {
            return 0;
        }

        pcon = http_con_fetch(mgmt);
        if (!pcon) {
            iodev_close_by(mgmt->pcore, iodev_id(pdev));
            return -100;
        }

        pcon->pdev = pdev;
        pcon->devid = iodev_id(pdev);
        iodev_para_set(pdev, (void *)pcon->conid);
 
        pcon->hl = hl;

        pcon->casetype = HTTP_SERVER;
        pcon->ssl_link = hl->ssl_link;

        str_cpy(pcon->srcip, iodev_rip(pcon->pdev));
        str_cpy(pcon->dstip, iodev_lip(pcon->pdev));
        pcon->srcport = iodev_rport(pcon->pdev);
        pcon->dstport = iodev_lport(pcon->pdev);
        pcon->createtime = time(&pcon->stamp);
        pcon->transbgn = pcon->stamp;
 
        pcon->rcv_state = HTTP_CON_READY;
        pcon->snd_state = HTTP_CON_SEND_READY;

#ifdef HAVE_OPENSSL
        if (pcon->ssl_link) {
            pcon->sslctx = http_listen_ssl_ctx_get(hl);
            pcon->ssl = http_ssl_new(pcon->sslctx, pcon);
            pcon->ssl_handshaked = 0;
            pcon->rcv_state = HTTP_CON_SSL_HANDSHAKING;
        }
#endif

        http_connection_accepted(mgmt, 1);
        http_mgmt_acceptcon_add(mgmt, pcon);

        if (pcon->life_timer)
            iotimer_stop(mgmt->pcore, pcon->life_timer);

        iodev_bind_epump(pdev, BIND_ONE_EPUMP, 0, 1);  //bind but not start polling

        /* The upcoming read/write event from pcon and the timeout event of life_timer
           will be pipelined to the current thread. It seems to degrade the efficiency
           of multi-CPU concurrent execution. But it reduces the risk of lock blocking/contention */

        pcon->life_timer = iotimer_start(mgmt->pcore,
                                  mgmt->conn_check_interval * 1000,
                                  t_http_cli_con_life, (void *)pcon->conid,
                                  http_pump, mgmt, iodev_epumpid(pdev));
 
        iodev_set_poll(pdev);
    }

    return 0;
}


int http_cli_recv (void * vmgmt, ulong conid)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon    * pcon = NULL;
    HTTPMsg    * msg = NULL;
    HTTPMsg    * imsg = NULL;
    int          i, ret = 0, num = 0;
    int          rcvnum = 0, err = 0;

    if (!mgmt) return -1;

    pcon = http_mgmt_con_get(mgmt, conid);
    if (!pcon) return -2;

    if (pcon->workerid == 0) 
        pcon->workerid = iodev_workerid(pcon->pdev);

    /* If the speed of receiving client data is faster than that of sending
       to the server, a large amount of data will accumulate in the memory,
       which will eventually lead to memory exhaustion and collapse. Congestion
       control should be activated by ignoring the read-ready event in the ePump
       framework. After that, the receiving buffer of the underlying TCP protocol
       stack will soon be full. TCP stack will start congestion control mechanism */
    if (http_cli_recv_cc(mgmt, conid) > 0)
        return 0;

#if defined(_WIN32) || defined(_WIN64)
    EnterCriticalSection(&pcon->rcvCS);
#else
    if (TryEnterCriticalSection(&pcon->rcvCS) != 0) { //already locked
        tolog(1, "TryLock: [%lu %lu/%d %s:%d %d] WkerID=%lu CurThID=%lu DevEPumpID=%lu DevWkerID=%lu\n",
              pcon->conid, iodev_id(pcon->pdev), iodev_fd(pcon->pdev),
              pcon->srcip, pcon->srcport, pcon->casetype, pcon->workerid,
          get_threadid(), iodev_epumpid(pcon->pdev), iodev_workerid(pcon->pdev));
        return 0;
    }
#endif

    while (1) {

        ret = http_con_read(pcon, pcon->rcvstream, &rcvnum, &err);

        if (rcvnum > 0) {
            http_overhead_recv(mgmt, rcvnum);
            pcon->total_recv += rcvnum;
        }

        if (ret < 0) {
            http_cli_con_crash(mgmt, conid, 1);
            LeaveCriticalSection(&pcon->rcvCS);
            return -100;
        }

        time(&pcon->stamp);
        if (pcon->read_ignored > 0)
            pcon->read_ignored = 0;

        num = frameL(pcon->rcvstream);
        if (rcvnum <= 0 && num <= 0) {
            /* no data in socket and rcvstream, just return and
               wait for Read-Ready notify */
            LeaveCriticalSection(&pcon->rcvCS);
            return 0;
        }
 
        if (pcon->httptunnel == 1 && pcon->tunnelself == 0) {
            ret = http_tunnel_srv_send(pcon, pcon->tunnelcon);
            if (ret < 0) {
               http_con_close(mgmt, pcon->tunnelconid);
               http_con_close(mgmt, conid);
            }
            LeaveCriticalSection(&pcon->rcvCS);
            return ret;
        }

        /* Multiple HTTP requests may be sent on a connection, so it is necessary to
           handle all requests circularly as soon as possible to avoid resource accumulation. */
        while (1) {
            if (http_mgmt_con_get(mgmt, conid) != pcon) {
                LeaveCriticalSection(&pcon->rcvCS);
                return 0;
            }

            if (frameL(pcon->rcvstream) < 10) break;

            ret = http_cli_recv_parse(pcon);
            if (ret < 0) {
                http_cli_con_crash(mgmt, conid, 1);
                LeaveCriticalSection(&pcon->rcvCS);
                return ret;

            } else if (ret == 0) { //need to wait for more data
                LeaveCriticalSection(&pcon->rcvCS);
                return 0;

            } else if (ret >= 100) { //Proxy HTTPMsg or FastCGIMsg
                continue; 

            } else {
                /* pcon->msg stores last receiving msg instance.
                   pcon may have multiple msg instances being handled by 
                   callback function before the msg.  */
                msg = pcon->msg;
                pcon->msg = NULL;

                if (!msg) continue;
    
                num = http_con_msg_num(pcon);
                if (num > 4) { 
                    //may be malicious request when over 5 HTTPMsgs are sent on one connection at the same time
                    http_con_msg_del(pcon, msg);
                    http_msg_close(msg);
                    msg = NULL;
                    break;
                }

                for (i = 0; num > 1 && i < num - 1; i++) {
                    imsg = arr_value(pcon->msg_list, i);
                    if (!imsg || imsg == msg) continue;
                    if (imsg->urihash == msg->urihash || (imsg->pathhash == msg->pathhash && num > 2)) {
                        http_con_msg_del(pcon, msg);
                        http_msg_close(msg);
                        msg = NULL;
                        break;
                    }
                }
                if (!msg) continue;

                /* If the current msg is the first message on the connection,
                   process the message, otherwise, do nothing, and wait for
                   the previous message to be processed. */
                if (msg && msg == http_con_msg_first(pcon))
                    http_msg_dispatch(pcon, msg);
            }
        } //end while(num > 10)

        if (rcvnum <= 0) break;
        if (http_mgmt_con_get(mgmt, conid) != pcon) break;

    } //end while (1)

    LeaveCriticalSection(&pcon->rcvCS);

    return 0;
}


/* return value:
 *   -1   : invalid entry augument
 *   -101 : no HTTPMsg instance exists while waiting body
 *   -102 : parsing body failed while waiting body
 *   -103 : HTTPMsg body-flag indicates no body but acutally in waiting body state
 *   -104 : request header is too large, possibly a malicious attack
 *   -105 : HTTPMsg allocate failed
 *   -106 : parse reqest header failed while waiting header
 *   -107 : parsing body failed while waiting header
 *   -108 : HTTPMsg body-flag invalid or error
 *   -109 : current HTTPMsg is proxied or fastcgi message, but server-side HTTPMsg/FastCGIMsg not exist
 *   -110 : transferring body to proxy HTTPMsg failed
 *   -111 : transferring body to FastCGIMsg failed
 *    0 : only partial request got, need to wait for more data
 *    1 : complete HTTP-Request with body data parsed successfully
 *    2 : complete HTTP-Request without body data parsed successfully
 *    100 : handled by proxied HTTPMsg successfully
 *    101 : handled by FastCGIMsg successfully
 */
int http_cli_recv_parse (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMsg  * msg = NULL;
    HTTPMgmt * mgmt = NULL;
    int        ret = 0; 
    long       num = 0;
    int64      hdrlen = 0;
    uint8    * pbyte = NULL;
    uint8    * pbgn = NULL;
    char       buf[2048];

    HTTPMsg  * proxymsg = NULL;
    FcgiMsg  * cgimsg = NULL;

    if (!pcon) return -1;

    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;

    num = frameL(pcon->rcvstream);
    if (num <= 0) {
        return 0;
    }

    if (pcon->rcv_state == HTTP_CON_READY) {
        pcon->rcv_state = HTTP_CON_WAITING_HEADER;
    }

    if (pcon->rcv_state == HTTP_CON_WAITING_BODY) {
        msg = pcon->msg;
        if (!msg) {
            return -101;
        }

        msg->stamp = time(0);

        /* if the msg is proxied for the client msg, call proxy_srv_send */
        if (msg == http_con_msg_first(pcon)) {
            if (msg->proxied) {
                if (msg->proxymsgid > 0 && (proxymsg = http_msg_mgmt_get(mgmt, msg->proxymsgid)) != NULL) {
                    if (http_proxy_srv_send(proxymsg->pcon, proxymsg) < 0) 
                        return -110;
                    return 100;
                } else {
                    if (msg->res_encoded && msg->res_status > 0) {
                        /* proxied HTTPMsg has been closed for some failure, current HTTPMsg also been
                           handled to reply error code. subsequent request body just descarded. */
                        return 0;
                    }

                    str_secpy(buf, sizeof(buf)-1, msg->req_line, msg->req_line_len);
                    tolog(1, "Panic: Msg[%lu %s] proxymsgid=%lu bodystream=%d has no proxymsg,"
                             " but %ld bytes coming. BodyFlag=%d BodyLen=%ld ioLen=%ld streamRcv=%ld"
                             " ResStatus=%d ResEncoded=%d ProxyMsg=%p"
                             " Con[%lu %s:%d num-req/res=%d/%d]\n",
                          msg->msgid, buf, msg->proxymsgid, frameL(msg->req_body_stream), num,
                          msg->req_body_flag, msg->req_body_length, msg->req_body_iolen, msg->req_stream_recv,
                          msg->res_status, msg->res_encoded, msg->proxymsg,
                          pcon->conid, pcon->srcip, pcon->srcport, pcon->reqnum, pcon->resnum);

                    if (frameL(msg->req_body_stream) > 2048*1024)
                        return -109;
                }
    
            } else if (msg->fastcgi) {
                if ((cgimsg = msg->fcgimsg) != NULL) {
                    if (http_fcgi_srv_send(cgimsg->pcon, cgimsg) < 0) return -111;
                    return 101;
                } else {
                    if (msg->res_encoded && msg->res_status > 0) {
                        /* FastCGIMsg has been closed for some failure, current HTTPMsg also
                           been handled to reply error code. subsequent request body just descarded. */
                        return 0;
                    }

                    str_secpy(buf, sizeof(buf)-1, msg->req_line, msg->req_line_len);
                    tolog(1, "Panic: Msg[%lu %s] bodystream=%d has no fastcgi-msg,"
                             " but %ld bytes coming. BodyFlag=%d BodyLen=%ld ioLen=%ld streamRcv=%ld"
                             " ResStatus=%d ResEncoded=%d ProxyMsg=%p"
                             " Con[%lu %s:%d num-req/res=%d/%d]\n",
                          msg->msgid, buf, frameL(msg->req_body_stream), num,
                          msg->req_body_flag, msg->req_body_length, msg->req_body_iolen, msg->req_stream_recv,
                          msg->res_status, msg->res_encoded, msg->proxymsg,
                          pcon->conid, pcon->srcip, pcon->srcport, pcon->reqnum, pcon->resnum);

                    if (frameL(msg->req_body_stream) > 2048*1024)
                        return -109;
                }
            }
        }

        switch (msg->req_body_flag) {
        case BC_CONTENT_LENGTH:
        case BC_TE:
            ret = http_cli_reqbody_parse(pcon, msg);
            if (ret < 0) {
                return -102;

            } else if (ret == 0) { //waiting more body
                pcon->rcv_state = HTTP_CON_WAITING_BODY;

            } else {
                pcon->rcv_state = HTTP_CON_READY;
                return 1;
            }
            break;

        default:
            return -103;
        }

    } else {
        pbgn = frameP(pcon->rcvstream);

        /* determine if http header got completely */
        pbyte = sun_find_bytes(pbgn, num, "\r\n\r\n", 4, NULL);
        if (!pbyte) {
            if (num > mgmt->cli_max_header_size) {
                /* request header is too large, possibly a malicious attack */
                return -104;
            }
            pcon->rcv_state = HTTP_CON_WAITING_HEADER;

            return 0;
        }
        hdrlen = pbyte + 4 - pbgn;

        pcon->msg = msg = http_msg_fetch(mgmt);
        if (!msg) {
            return -105;
        }

        msg->msgtype = 1; //receiving request

        msg->workerid = iodev_workerid(pcon->pdev);

        pcon->reqnum++;
        msg->pcon = pcon;
        msg->conid = pcon->conid;
        msg->hl = pcon->hl;
        msg->hc = NULL;
        strcpy(msg->srcip, pcon->srcip);
        strcpy(msg->dstip, pcon->dstip);
        msg->srcport = pcon->srcport;
        msg->dstport = pcon->dstport;

        msg->ssl_link = pcon->ssl_link;

        msg->state = HTTP_MSG_REQUEST_RECVING;

        msg->req_header_length = hdrlen;
        if (hdrlen > 0) {
            /* remove the last 2 trailer "\r\n" */
            frame_put_nlastp(&msg->req_header_stream, pbgn, hdrlen-2); 
            frame_del_first(pcon->rcvstream, hdrlen);
        }
        msg->req_stream_recv += hdrlen;

        /* add to the msg queue of current HTTPCon for pipeline handling or tracing */
        http_con_msg_add(pcon, msg);

        ret = http_req_parse_header(msg);

        if (ret < 0) return -106;

        /* request-line contains path/query only, uri doesn't include scheme/host
         * adjust it from Host header to form one complete uri */
        if (msg->req_url_type == 0) //0-relative uri  1-absolute uri  2-connect uri
            http_req_set_absuri(msg);

        pcon->keepalive = msg->req_conn_keepalive;

        if (arr_num(pcon->msg_list) == 1 && msg->req_methind == HTTP_METHOD_CONNECT) {
            pcon->tunnel_state = HTTP_TUNNEL_DNSING;
        }

        if (http_req_verify(msg) < 0) {
            return -116;
        }

        /* set DocURI and match the request path with configured Host and Location */
        if (msg->req_url_type == 0 && msg->req_methind != HTTP_METHOD_CONNECT) { //exclude CONNECT method
            http_req_set_docuri(msg, frameP(msg->uri->uri), frameL(msg->uri->uri), 0, 0);
        }

        /* if set the check callback, all requests including proxy mode will be checked */
        if (mgmt->req_check) {
            msg->GetRealFile(msg, buf, sizeof(buf)-1);
            (*mgmt->req_check)(mgmt->req_checkobj, msg, buf);
        }

        /* determine if request body is following, set the rcv_state of HTTPCon */
        if ( ( msg->req_body_flag == BC_CONTENT_LENGTH &&
               msg->req_body_length > 0 ) ||
             msg->req_body_flag == BC_TE)
        {
            pcon->rcv_state = HTTP_CON_WAITING_BODY;
        } else {
            pcon->rcv_state = HTTP_CON_READY;
            msg->req_gotall_body = 1;
        }

        /* Multiple HTTP requests may be received on the TCP connection. If the first
           HTTP request message is still being processed, subsequent messages need to
           be queued for its processing */
        if (msg == http_con_msg_first(pcon)) {
            if (http_proxy_handle(msg) >= 0)
                return 100;

            if (http_fcgi_handle(msg) >= 0)
                return 101;
        } else {
            if (msg && http_proxy_examine(msg) < 0)
                http_fcgi_examine(msg);
        }

        return http_reqbody_handle(msg);
    }

    return 0;
}

int http_reqbody_handle (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPCon  * pcon = NULL;
    int        ret = 0;

    if (!msg) return -1;

    pcon = (HTTPCon *)msg->pcon;
    if (!pcon) return -2;

    /* HTTP POST/PUT request body may be encoded as following enctype:
         (1) application/x-www-form-urlencoded
         (2) multipart/form-data
         (3) application/json
         (4) text/xml
         (5) application/octet-stream
     */

    switch (msg->req_body_flag) {
    case BC_CONTENT_LENGTH:
    case BC_TE:
        ret = http_cli_reqbody_parse(pcon, msg);
        if (ret < 0) {
            return -107;
        } else if (ret == 0) { //waiting more body
            pcon->rcv_state = HTTP_CON_WAITING_BODY;
        } else {
            pcon->rcv_state = HTTP_CON_READY;

            return 1;
        }
        break;

    case BC_TE_INVALID:
    case BC_UNKNOWN:
        return -108;

    case BC_NONE:
    case BC_TUNNEL:
    default:
        pcon->rcv_state = HTTP_CON_READY;
        msg->req_gotall_body = 1;
        return 2;
        break;
    }

    return 0;
}

int http_cli_reqbody_parse (void * vcon, void * vmsg)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    char     * pbody = NULL;
    int        bodylen = 0;
    int64      restlen = 0;
    int        ret, rmlen = 0;

    if (!pcon) return -1;
    if (!msg) return -2;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -3;

    if (msg->req_gotall_body) return 1;

    pbody = frameP(pcon->rcvstream);
    bodylen = frameL(pcon->rcvstream);
     
    switch (msg->req_body_flag) {

    case BC_CONTENT_LENGTH: 

        restlen = msg->req_body_length - msg->req_body_iolen;
        if (restlen <= 0) {
            msg->req_gotall_body = 1;
            return 1;
        }

        if (bodylen >= restlen)
            bodylen = restlen;

        if (mgmt->cli_body_cache && 
            msg->req_body_length >= mgmt->cli_body_cache_threshold &&
            !msg->req_file_handle)
        {
            http_request_cache_init(msg);

            if (msg->req_file_handle) {
                frame_filefd_write(msg->req_body_stream, native_file_fd(msg->req_file_handle), 0);
                frame_empty(msg->req_body_stream);
            }
        }

        msg->req_body_iolen += bodylen;
        msg->req_stream_recv += bodylen;

        if (msg->req_file_cache && msg->req_file_handle) {
            if (msg->fastcgi) 
                fcgimsg_stdin_encode(pbody, bodylen, NULL, 0, NULL, msg->req_file_handle, NULL);
            else
                native_file_write(msg->req_file_handle, pbody, bodylen);

        } else {
            if (msg->req_body_stream == NULL)
                msg->req_body_stream = frame_alloc(bodylen + 256, msg->alloctype, msg->kmemblk);
            if (msg->fastcgi) 
                fcgimsg_stdin_encode(pbody, bodylen, NULL, 0, msg->req_body_stream, NULL, NULL);
            else
                frame_put_nlastp(&msg->req_body_stream, pbody, bodylen);
        }

        frame_del_first(pcon->rcvstream, bodylen);

        if (msg->req_body_iolen >= msg->req_body_length) {
            goto gotallbody;
        }

        return 0;

    case BC_TE:

        /* Chunk format as following:
         * 24E5CRLF            #chunk-sizeCRLF  (first chunk begin)
         * 24E5(byte)CRLF      #(chunk-size octet)CRLF
         * 38A1CRLF            #chunk-sizeCRLF  (another chunk begin)
         * 38A1(byte)CRLF      #(chunk-size octet)CRLF
         * ......              #one more chunks may be followed
         * 0CRLF               #end of all chunks
         * X-bid-for: abcCRLF  #0-more HTTP Headers as entity header
         * .....               #one more HTTP headers with trailing CRLF
         * CRLF
         */
        if (msg->req_chunk == NULL)
            msg->req_chunk = http_chunk_alloc(msg->alloctype, msg->kmemblk);

        if (http_chunk_gotall(msg->req_chunk)) {
            msg->req_gotall_body = 1; 
            return 1;
        }
   
        ret = http_chunk_add_bufptr(msg->req_chunk, pbody, bodylen, &rmlen);
        if (ret < 0) return -30;

        msg->req_body_iolen += chunk_rest_size(http_chunk_obj(msg->req_chunk), 0);
        msg->req_body_length += chunk_rest_size(http_chunk_obj(msg->req_chunk), 0);

        if (mgmt->cli_body_cache && 
            msg->req_body_length >= mgmt->cli_body_cache_threshold &&
            !msg->req_file_handle)
        {
            http_request_cache_init(msg);

            if (msg->req_file_handle) {
                frame_filefd_write(msg->req_body_stream, native_file_fd(msg->req_file_handle), 0);
                frame_empty(msg->req_body_stream);
            }
        }

        if (msg->req_file_handle) {
            if (msg->fastcgi) 
                fcgimsg_stdin_encode(pbody, rmlen, NULL, 0, NULL, msg->req_file_handle, NULL);
            else
                chunk_write_file(http_chunk_obj(msg->req_chunk), native_file_fd(msg->req_file_handle), 0, -1, 0);

        } else {
            if (msg->req_body_stream == NULL)
                msg->req_body_stream = frame_alloc(rmlen, msg->alloctype, msg->kmemblk);
            if (msg->fastcgi) 
                fcgimsg_stdin_encode(pbody, rmlen, NULL, 0, msg->req_body_stream, NULL, NULL);
            else
                chunk_write_framep(http_chunk_obj(msg->req_chunk), &msg->req_body_stream, 0, -1, 0);
        }

        chunk_remove(http_chunk_obj(msg->req_chunk), msg->req_body_length, 0); 

        msg->req_stream_recv += rmlen;
        if (rmlen > 0)
            frame_del_first(pcon->rcvstream, rmlen);

        if (http_chunk_gotall(msg->req_chunk)) {
            goto gotallbody;
        }
   
        return 0;

    default:
        return -10;
    }

    return 0;

gotallbody:
    msg->req_gotall_body = 1;

    if (msg->req_file_handle) {
        chunk_add_filefd(msg->req_body_chunk,
                         native_file_fd(msg->req_file_handle),
                         0, -1);
    } else {
        chunk_add_bufptr(msg->req_body_chunk,
                         frameP(msg->req_body_stream),
                         frameL(msg->req_body_stream), NULL, NULL);
    }

    chunk_set_end(msg->req_body_chunk);

    if (msg->proxied || msg->fastcgi) return 1;
 
    if (msg->req_content_type && msg->req_contype_len > 0) {
        if (str_ncasecmp(msg->req_content_type, "application/x-www-form-urlencoded", 33) == 0) {
            if (!msg->req_form_kvobj) {
                msg->req_form_kvobj = kvpair_init(37, "&", "=");
            }
     
            chunk_ptr(msg->req_body_chunk, 0, NULL, (void **)&pbody, &restlen);
            kvpair_decode(msg->req_form_kvobj, pbody, restlen);
    
        } else if (str_ncasecmp(msg->req_content_type, "application/json", 16) == 0) {
            if (!msg->req_form_json) {
                msg->req_form_json = json_init(0, 0, 0);
            }
     
            chunk_ptr(msg->req_body_chunk, 0, NULL, (void **)&pbody, &restlen);
            json_decode(msg->req_form_json, pbody, restlen, 1, 0);
    
        } else if (str_ncasecmp(msg->req_content_type, "multipart/form-data", 19) == 0) {
            http_form_multipart_parse(msg, NULL);
        }
    }

    return 1;
}


int http_cli_send_probe (void * vmgmt, ulong conid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;
    HTTPMsg  * msg = NULL;
    int        num = 0;
 
    if (!mgmt) return -1;

    pcon = http_mgmt_con_get(mgmt, conid);
    if (!pcon) return -2;
 
    if (pcon->snd_state < HTTP_CON_SEND_READY) return -100;
 
    num = arr_num(pcon->msg_list);
    if (num <= 0) {
        if (pcon->snd_state == HTTP_CON_FEEDING)
            pcon->snd_state = HTTP_CON_SEND_READY;
        return 0;
    }
 
    msg = (HTTPMsg *)arr_value(pcon->msg_list, 0);
    if (!msg || msg->res_encoded == 0) {
        if (pcon->snd_state == HTTP_CON_FEEDING)
            pcon->snd_state = HTTP_CON_SEND_READY;
        return 0;
    }
 
    if (pcon->snd_state == HTTP_CON_FEEDING) {
        return 0;
    }
 
    iodev_add_notify(pcon->pdev, RWF_WRITE);
 
    return 0;
}

 
int http_cli_send (void * vmgmt, ulong conid)
{
    HTTPMgmt    * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon     * pcon = NULL;
    HTTPMsg     * msg = NULL;
 
    void        * chunk = NULL;
    chunk_vec_t   iovec;
 
    uint8         httpchunk = 0;
    int           ret = 0;
    int64         filepos = 0;
    int64         sentnum = 0;
    int           num = 0;
    int           err = 0;
    uint8         shutdown = 0;
    uint8         closecon = 0;
 
    if (!mgmt) return -1;

    pcon = http_mgmt_con_get(mgmt, conid);
    if (!pcon) return -2;

    if (pcon->snd_state < HTTP_CON_SEND_READY)
        return -100;
 
    if (pcon->httptunnel == 1 && pcon->tunnelself == 0 && arr_num(pcon->msg_list) <= 0) 
        return http_tunnel_cli_send(pcon->tunnelcon, pcon);

    if (pcon->snd_state == HTTP_CON_FEEDING)
        return 0;
 
    pcon->snd_state = HTTP_CON_FEEDING;
 
    while (arr_num(pcon->msg_list) > 0 &&
           pcon->snd_state == HTTP_CON_FEEDING)
    {
 
        msg = http_con_msg_first(pcon);
        if (!msg) {
            pcon->snd_state = HTTP_CON_SEND_READY;
            break;
        }
 
        if (msg->res_encoded == 0) {
            /* If the callback of the current HTTP request has not yet completed
               processing, just return and do nothing */
            pcon->snd_state = HTTP_CON_SEND_READY;

            http_msg_dispatch(pcon, msg);

            return 0;
        }
 
        httpchunk = msg->res_body_flag == BC_TE ? 1 : 0;

        chunk = msg->res_body_chunk;
        filepos = msg->res_stream_sent;

        if (filepos > 0 && chunk_get_end(chunk, filepos, httpchunk)) {
            /* response of current HTTPMsg has been successfully sent to the client, release the msg */
            http_con_msg_del(pcon, msg);
            http_msg_close(msg);
            continue;
        }

        if (chunk_has_file(chunk) > 0) {
            if (iodev_tcp_nodelay(pcon->pdev) == TCP_NODELAY_SET) {
                iodev_tcp_nodelay_set(pcon->pdev, TCP_NODELAY_UNSET);
            }
 
            if (iodev_tcp_nopush(pcon->pdev) == TCP_NOPUSH_UNSET) {
                iodev_tcp_nopush_set(pcon->pdev, TCP_NOPUSH_SET);
            }
        }
 
        for (sentnum = 0; chunk_get_end(chunk, filepos, httpchunk) == 0; ) {
 
            memset(&iovec, 0, sizeof(iovec));
            ret = chunk_vec_get(chunk, filepos, &iovec, httpchunk);
 
            if (ret < 0 || (iovec.size > 0 && iovec.vectype != 1 && iovec.vectype != 2)) {
                pcon->snd_state = HTTP_CON_IDLE;
                http_cli_con_crash(mgmt, conid, 1);
                return ret;
            }
 
            if (iovec.size == 0) {
                /* no available data to send, waiting for more data... */
                pcon->snd_state = HTTP_CON_SEND_READY;

                /* After all the octets in the buffer are sent to the client, the uncongestion
                   process will be initiated. The connection on the server side is checked: if
                   its read event notification mechanism was previously removed, re-add it now. */
                http_cli_send_cc(mgmt, conid);

                if (msg->cacheon && msg->res_cache_info) {
                    /* read the cache file again. if no data in it, request the origin server for more */ 
                    return http_proxy_cli_cache_send(pcon, msg);
                }

                return 0;
            }

            err = 0;
            if (iovec.vectype == 2) { //sendfile

#if defined(_WIN32) || defined(_WIN64)
                ret = http_con_sendfile(pcon, (int)iovec.filefd, iovec.fpos, iovec.size , &num, &err);
#else
                ret = http_con_sendfile(pcon, iovec.filefd, iovec.fpos, iovec.size , &num, &err);
#endif
                if (ret < 0) {
                    shutdown = 1;
                }
 
            } else if (iovec.vectype == 1) { //mem buffer, writev
                ret = http_con_writev(pcon, iovec.iovs, iovec.iovcnt, &num, &err);

                if (ret < 0) {
                    shutdown = 1;
                }
            }

            filepos += num;
            msg->res_stream_sent += num;
            sentnum += num;
 
            http_overhead_sent(pcon->mgmt, num);
            msg->stamp = time(&pcon->stamp);

            /* When HTTP connection serves as a tunnel, data sent to the client
               is not counted in the connection */
            if (pcon->httptunnel != 1 && pcon->httptunnel != 2)
                pcon->total_sent += num;
 
            /* remove the sent ChunkEntity-es in msg->res_body_chunk.
               release the sent frame objects for zero-copy purposes to hold received
               data from origin server. */
            http_cli_send_final(msg);

            if (shutdown) break;

#ifdef UNIX
            if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK) { //EAGAIN
#elif defined(_WIN32) || defined(_WIN64)
            if (err == WSAEWOULDBLOCK) {
#else
            if (num == 0) {
#endif
                pcon->snd_state = HTTP_CON_SEND_READY;
                iodev_add_notify(pcon->pdev, RWF_WRITE);

                /* After all the octets in the buffer are sent to the client, the uncongestion
                   process will be initiated. The connection on the server side is checked: if
                   its read event notification mechanism was previously removed, re-add it now. */
                if (sentnum > 0)
                    http_cli_send_cc(mgmt, conid);

                return 0;
            }
        }
 
        if (chunk_get_end(chunk, msg->res_stream_sent, httpchunk) == 1) {
            if (msg->res_status >= 400)
                closecon++;

            if (msg->req_ver_major < 1 || (msg->req_ver_major == 1 && msg->req_ver_minor == 0))
                closecon++;

            if (msg->req_conn_keepalive == 0)
                closecon++;

            /* send response to client successfully */
            http_con_msg_del(pcon, msg);
            http_msg_close(msg);

            pcon->resnum++;
            pcon->transbgn = time(NULL);

            /* go on sending another HTTPMsg */
        }
 
        if (shutdown) {
            pcon->snd_state = HTTP_CON_IDLE;
            http_cli_con_crash(mgmt, conid, 1);
            return ret;
        }

    } //end while
 
    if (closecon) {
        pcon->snd_state = HTTP_CON_IDLE;
        http_cli_con_crash(mgmt, conid, 1);
        return ret;
    }

    pcon->snd_state = HTTP_CON_SEND_READY;
 
    /* the response has been sent to client. the current HTTPCon
     * should send the next HTTPMsg in the FIFO queue. */
    if ((msg = http_con_msg_first(pcon)) && msg->res_encoded) {
        iodev_add_notify(pcon->pdev, RWF_WRITE);
    }
 
    return 0;
}

int http_cli_send_final (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    frame_p    frm = NULL;
    int        i, num;
    int        fnum = 0;
    uint8      httpchunk = 0;
 
    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;

    httpchunk = msg->res_body_flag == BC_TE ? 1 : 0;

    fnum = chunk_remove(msg->res_body_chunk, msg->res_stream_sent, httpchunk);
 
    if (fnum <= 0)
        return 0;
 
    num = arr_num(msg->res_rcvs_list);
    for (i = 0; i < num; i++) {
        frm = arr_value(msg->res_rcvs_list, i);
 
        fnum = chunk_bufptr_porig_find(msg->res_body_chunk, frm);
        if (fnum <= 0) {
            arr_delete(msg->res_rcvs_list, i);
            i--; num--;

            frame_free(frm);
        }
    }
 
    return 1;
}


int http_cli_con_lifecheck (void * vmgmt, ulong conid)
{
    HTTPMgmt * mgmt = (HTTPMgmt *)vmgmt;
    HTTPCon  * pcon = NULL;
    time_t     curt = 0;
    int        num = 0;

    if (!mgmt) return -1;

    pcon = http_mgmt_con_get(mgmt, conid);
    if (!pcon) return -2;

    num = arr_num(pcon->msg_list);
    time(&curt);

    if (pcon->httptunnel == 1) {
        if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->tunnel_keepalive_time) {
            return http_con_close(mgmt, conid);
        }
        goto starttimer;
    }

    if (num <= 0) { //before got one complete header, after replying response

        if (pcon->rcv_state <= HTTP_CON_READY) {
            if (pcon->reqnum > 0) {
                /* after one or more transactions of request receiving and response sending,
                   Now waiting some time for new incoming request data from client. */
                if (pcon->keepalive) { 
                    if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->cli_keepalive_time) {
                        /* send/recv one or more requests, now no request coming
                           for keepalive time */
                        return http_con_close(mgmt, conid);
                    }

                } else {
                    /* send/recv one or more requests, now close connection
                       while no keepalive */
                    return http_con_close(mgmt, conid);
                }

            } else if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->cli_conn_idle_time) {
                /* built connection, no request comes in */
                return http_con_close(mgmt, conid);
            }

        } else if (pcon->rcv_state == HTTP_CON_SSL_HANDSHAKING) {
            if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->cli_header_time) {
                /* SSL handshaking in process, it last too long */
                return http_con_close(mgmt, conid);
            }

        } else if (pcon->rcv_state == HTTP_CON_WAITING_HEADER) {
            /* has got partial HTTP-request header */
            if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->cli_header_idletime) {
                /* after got partial request header, no byte send out for sometime */
                return http_con_close(mgmt, conid);

            } else if (pcon->stamp > pcon->transbgn && 
                       pcon->stamp - pcon->transbgn >= mgmt->cli_header_time)
            {
                /* not got one full request header, from first byte to now, 
                   close it when exceeding max waiting time */
                return http_con_close(mgmt, conid);
            }
        }

    } else { //num > 0, after got one complete request header, before replying succ

        if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->cli_request_handle_time) {
            /* after received header, waiting for proxy and upper layer callback handling */
            return http_con_close(mgmt, conid);
        }
    }

starttimer:
    pcon->life_timer = iotimer_start(mgmt->pcore,
                                  mgmt->conn_check_interval * 1000,
                                  t_http_cli_con_life, (void *)conid,
                                  http_pump, mgmt, iodev_epumpid(pcon->pdev));
    return 0;
}

