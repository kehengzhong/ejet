/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"
#include "http_con.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_pump.h"
#include "http_cli_io.h"
#include "http_listen.h"
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


int http_cli_con_crash (void * vcon, int closelad)
{
    HTTPCon  * clicon = (HTTPCon *)vcon;
    HTTPMgmt * mgmt = NULL;
    HTTPMsg  * climsg = NULL;
    HTTPMsg  * srvmsg = NULL;
    HTTPCon  * srvcon = NULL;
    FcgiSrv  * cgisrv = NULL;
    FcgiMsg  * cgimsg = NULL;
    FcgiCon  * cgicon = NULL;

    if (!clicon) return -1;

    mgmt = (HTTPMgmt *)clicon->mgmt;
    if (!mgmt) return -2;

    climsg = http_con_msg_first(clicon);
    if (!closelad || !climsg)
        return http_con_close(clicon);

    if (climsg->proxied == 1 && (srvmsg = climsg->proxymsg)) {
        srvcon = http_mgmt_con_get(mgmt, srvmsg->conid);
        if (srvcon)
            http_con_close(srvcon);
    }

    else if (climsg->fastcgi == 1 && (cgimsg = climsg->fcgimsg)) {
        cgisrv = (FcgiSrv *)cgimsg->srv;
        cgicon = http_fcgisrv_con_get(cgisrv, cgimsg->conid);
        if (cgicon)
            http_fcgicon_close(cgicon);
    }

    else if (clicon->httptunnel && clicon->tunnelcon) {
        http_con_close(clicon->tunnelcon);
    }

    return http_con_close(clicon);
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
        pdev = eptcp_accept(mgmt->pcore, listendev, 
                            (void *)NULL, &ret, 
                            http_pump, mgmt, BIND_NONE);
        if (pdev == NULL) {
            return 0;
        }

        pcon = http_con_fetch(mgmt);
        if (!pcon) {
            iodev_close(pdev);
            return -100;
        }

        pcon->pdev = pdev;
        iodev_para_set(pdev, (void *)pcon->conid);
 
        pcon->hl = hl;

        pcon->casetype = HTTP_SERVER;
        pcon->reqdiag = hl->reqdiag;
        pcon->reqdiagobj = hl->reqdiagobj;

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
        
        if (pcon->life_timer)
            iotimer_stop(pcon->life_timer);

        /* the upcoming R/W events from pcon and the timeout event of life_timer will
           pipelined to delivered to current thread. it seems to degrade the efficiency
           of multiple CPU concurrent execution. but it lowers the risk of blocking/contention
           from locks */

        pcon->life_timer = iotimer_start(mgmt->pcore,
                                  mgmt->conn_check_interval * 1000,
                                  t_http_cli_con_life, (void *)pcon->conid,
                                  http_pump, mgmt);
 
        iodev_bind_epump(pdev, BIND_CURRENT_EPUMP, NULL);
    }

    return 0;
}


int http_cli_recv (void * vcon)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMgmt   * mgmt = NULL;
    HTTPMsg    * msg = NULL;
    ulong        conid = 0;
    int          ret = 0, num = 0;
    int          err = 0;

    if (!pcon) return -1;

    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;

    /* If the receiving speed of client side is greater than the sending  
       speed of server side, a great deal of data will be piled up in memory.
       Congestion control should be activated by neglecting the read-ready event.
       After that, receving buffer of underlying TCP will be full soon.
       TCP stack will start congestion control mechanism */
    if (http_cli_recv_cc(pcon) > 0)
        return 0;

    conid = pcon->conid;

    while (1) {

        ret = http_con_read(pcon, pcon->rcvstream, &num, &err);
        if (ret < 0) {
            http_cli_con_crash(pcon, 1);
            return -100;
        }

        time(&pcon->stamp);
        if (pcon->read_ignored > 0)
            pcon->read_ignored = 0;

        if (num > 0) {
            http_overhead_recv(mgmt, num);
        } else if (frameL(pcon->rcvstream) <= 0) {
            /* no data in socket and rcvstream, just return and
               wait for Read-Ready notify */
            return 0;
        }
 
        num = frameL(pcon->rcvstream);

        if (pcon->httptunnel && pcon->tunnelself == 0) {
            ret = http_tunnel_srv_send(pcon, pcon->tunnelcon);
            if (ret < 0) {
               http_con_close(pcon->tunnelcon);
               http_con_close(pcon);
            }
            return ret;
        }

        ret = http_cli_recv_parse(pcon);
        if (ret < 0) {
            http_cli_con_crash(pcon, 1);
            return ret;

        } else if (ret == 0) {
            return 0;

        } else {
            /* pcon->msg stores current receiving msg instance.
               pcon may have multiple msg instances being handled by 
               callback function before the msg.
             */
            /* msg = http_con_msg_last(pcon); */
            msg = pcon->msg;
            pcon->msg = NULL;

            if (!msg) continue;

            if (msg && msg->proxied == 0) {
                http_msg_handle(pcon, msg);

                if (http_mgmt_con_get(mgmt, conid) != pcon)
                    return 0;
            }
        }

    } //end while (1)

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
 *    0 : only partial request got, need to wait for more data
 *    1 : complete HTTP-Request with body data parsed successfully
 *    2 : complete HTTP-Request without body data parsed successfully
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
        /* msg assignments as following 2 methods are right */
        /* msg = http_con_msg_first(pcon); */
        msg = pcon->msg;
        if (!msg) {
            return -101;
        }

        msg->stamp = time(0);

        /* if the msg is proxied for the client msg, call proxy_srv_send */
        if (msg->proxied) {
            proxymsg = msg->proxymsg;

            if (proxymsg && proxymsg->pcon)
                http_proxy_srv_send(proxymsg->pcon, proxymsg);

            return 0;

        } else if (msg->fastcgi) {
            cgimsg = msg->fcgimsg;

            if (cgimsg && cgimsg->pcon)
                http_fcgi_srv_send(cgimsg->pcon, cgimsg);

            return 0;
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
        pbyte = kmp_find_bytes(pbgn, num, "\r\n\r\n", 4, NULL);
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

        pcon->reqnum++;
        msg->pcon = pcon;
        msg->hl = pcon->hl;
        msg->conid = pcon->conid;
        strcpy(msg->srcip, pcon->srcip);
        strcpy(msg->dstip, pcon->dstip);
        msg->srcport = pcon->srcport;
        msg->dstport = pcon->dstport;

        msg->ssl_link = pcon->ssl_link;

        msg->state = HTTP_MSG_REQUEST_RECVING;

        msg->req_header_length = hdrlen;
        if (hdrlen > 0) {
            /* remove the last 2 trailer "\r\n" */
            frame_put_nlast(msg->req_header_stream, pbgn, hdrlen-2); 
            frame_del_first(pcon->rcvstream, hdrlen);
        }
        msg->req_stream_recv += hdrlen;

        ret = http_req_parse_header(msg);
        if (ret < 0) return -106;

        /* request-line contains path/query only, uri doesn't include scheme/host
         * adjust it from Host header to form one complete uri */
        http_req_set_absuri(msg);

        /* add to the msg queue of current HTTPCon for pipeline handling or tracing */
        http_con_msg_add(pcon, msg);

        pcon->keepalive = msg->req_conn_keepalive;

        if (http_req_verify(msg) < 0) {
            return -116;
        }

        /* set DocURI and match the request path with configured Host and Location */
        if (msg->req_url_type == 0 && msg->req_methind != HTTP_METHOD_CONNECT) { //CONNECT method
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
        }

#if defined _DEBUG
  print_request(msg, stdout);
#endif

        if (http_proxy_handle(msg) >= 0)
            return 0;
 
        if (http_fcgi_handle(msg) >= 0)
            return 0;

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

    pbody = frameP(pcon->rcvstream);
    bodylen = frameL(pcon->rcvstream);
     
    switch (msg->req_body_flag) {

    case BC_CONTENT_LENGTH: 

        restlen = msg->req_body_length - msg->req_body_iolen;
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

        if (msg->req_file_cache && msg->req_file_handle) {
            native_file_write(msg->req_file_handle, pbody, bodylen);

        } else {
            frame_put_nlast(msg->req_body_stream, pbody, bodylen);
        }

        frame_del_first(pcon->rcvstream, bodylen);
        msg->req_body_iolen += bodylen;
        msg->req_stream_recv += bodylen;

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
        if (http_chunk_gotall(msg->req_chunk))
            return 1;
   
        ret = http_chunk_add_bufptr(msg->req_chunk, pbody, bodylen, &rmlen);
        if (ret < 0) return -30;

        msg->req_chunk_iolen += chunk_rest_size(http_chunk_obj(msg->req_chunk), 0);
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
            chunk_readto_file(http_chunk_obj(msg->req_chunk), native_file_fd(msg->req_file_handle), 0, -1, 0);

        } else {
            chunk_readto_frame(http_chunk_obj(msg->req_chunk), msg->req_body_stream, 0, -1, 0);
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

    if (msg->req_file_handle) {
        chunk_add_filefd(msg->req_body_chunk,
                         native_file_fd(msg->req_file_handle),
                         0, -1);
    } else {
        chunk_add_bufptr(msg->req_body_chunk,
                         frameP(msg->req_body_stream),
                         frameL(msg->req_body_stream), NULL, NULL);
    }

    http_form_multipart_parse(msg, NULL);

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
    
        }
    }

    return 1;
}


int http_cli_send_probe (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMsg  * msg = NULL;
    int        num = 0;
 
    if (!pcon) return -1;
 
    if (pcon->snd_state < HTTP_CON_SEND_READY) return -100;
 
    num = arr_num(pcon->msg_list);
    if (num <= 0) {
        if (pcon->snd_state == HTTP_CON_FEEDING)
            pcon->snd_state = HTTP_CON_SEND_READY;
        return 0;
    }
 
    msg = (HTTPMsg *)arr_value(pcon->msg_list, 0);
    if (!msg || msg->issued <= 0) {
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

 
int http_cli_send (void * vcon)
{
    HTTPCon     * pcon = (HTTPCon *)vcon;
    HTTPMgmt    * mgmt = NULL;
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
 
    if (!pcon) return -1;
 
    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;
 
    if (pcon->snd_state < HTTP_CON_SEND_READY)
        return -100;
 
    if (pcon->httptunnel && pcon->tunnelself == 0 && arr_num(pcon->msg_list) <= 0) 
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
 
        if (msg->proxied && (!msg->cacheon || !msg->res_cache_info)) {
            httpchunk = 0;
        } else {
            httpchunk = msg->res_body_flag == BC_TE ? 1 : 0;
        }

        chunk = msg->res_body_chunk;
        filepos = msg->res_stream_sent;

        if (msg->issued <= 0 || chunk_get_end(chunk, filepos, httpchunk)) {
            /* when the callback of http request not finished handling,
               or the reponse has been sent to client, just do nothing and return */
            pcon->snd_state = HTTP_CON_SEND_READY;
            return 0;
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
                http_cli_con_crash(pcon, 1);
                return ret;
            }
 
            if (iovec.size == 0) {
                /* no available data to send, waiting for more data... */
                pcon->snd_state = HTTP_CON_SEND_READY;

                /* all octets in buffer are sent to client and de-congesting process 
                   should be started. connection of server-side is checked to add Read notification
                   if it's removed before */
                http_cli_send_cc(pcon);

                if (msg->cacheon && msg->res_cache_info) {
                    /* read cache file again, if no data in cache file, request it from origin */
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
 
            /* remove the sent ChunkEntity-es in msg->res_body_chunk.
               release the already sent frame objects holding received data from 
               origin server for zero-copy purpose. */
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

                /* all octets in buffer are sent to client and de-congesting process 
                   should be started. connection of server-side is checked to add Read notification
                   if it's removed before */
                if (sentnum > 0)
                    http_cli_send_cc(pcon);

                return 0;
            }
        }
 
        if (chunk_get_end(chunk, msg->res_stream_sent, httpchunk) == 1) {
            if (msg->res_status >= 400)
                closecon++;

            if (msg->req_ver_major < 1 || (msg->req_ver_major == 1 && msg->req_ver_minor == 0))
                closecon++;

            /* send response to client successfully */
            http_con_msg_del(pcon, msg);
            http_msg_close(msg);

            pcon->transbgn = time(NULL);

            /* go on sending another HTTPMsg */
        }
 
        if (shutdown) {
            pcon->snd_state = HTTP_CON_IDLE;
            http_cli_con_crash(pcon, 1);
            return ret;
        }

    } //end while
 
    if (closecon) {
        pcon->snd_state = HTTP_CON_IDLE;
        http_cli_con_crash(pcon, 1);
        return ret;
    }

    pcon->snd_state = HTTP_CON_SEND_READY;
 
    /* the response has been sent to client. the current HTTPCon
     * should send the next HTTPMsg in the FIFO queue. */
    if (arr_num(pcon->msg_list) > 0) {
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
 
    if (!msg) return -1;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;

    fnum = chunk_remove(msg->res_body_chunk,
                        msg->res_stream_sent,
                        msg->res_body_flag == BC_TE ? 1 : 0);
    if (fnum <= 0)
        return 0;
 
    num = arr_num(msg->res_rcvs_list);
    for (i = 0; i < num; i++) {
        frm = arr_value(msg->res_rcvs_list, i);
 
        fnum = chunk_bufptr_porig_find(msg->res_body_chunk, frm);
        if (fnum <= 0) {
            arr_delete(msg->res_rcvs_list, i);
            frame_free(frm);
            i--; num--;
        }
    }
 
    return 1;
}


int http_cli_con_lifecheck (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMgmt * mgmt = NULL;
    time_t     curt = 0;
    int        num = 0;

    if (!pcon) return -1;

    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;

    num = arr_num(pcon->msg_list);
    time(&curt);

    if (pcon->httptunnel) {
        if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->tunnel_keepalive_time) {
            return http_con_close(pcon);
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
                        return http_con_close(pcon);
                    }

                } else {
                    /* send/recv one or more requests, now close connection
                       while no keepalive */
                    return http_con_close(pcon);
                }

            } else if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->cli_conn_idle_time) {
                /* built connection, no request comes in */
                return http_con_close(pcon);
            }

        } else if (pcon->rcv_state == HTTP_CON_SSL_HANDSHAKING) {
            if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->cli_header_time) {
                /* SSL handshaking in process, it last too long */
                return http_con_close(pcon);
            }

        } else if (pcon->rcv_state == HTTP_CON_WAITING_HEADER) {
            /* has got partial HTTP-request header */
            if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->cli_header_idletime) {
                /* after got partial request header, no byte send out for sometime */
                return http_con_close(pcon);

            } else if (pcon->stamp > pcon->transbgn && 
                       pcon->stamp - pcon->transbgn >= mgmt->cli_header_time)
            {
                /* not got one full request header, from first byte to now, 
                   close it when exceeding max waiting time */
                return http_con_close(pcon);
            }
        }

    } else { //num > 0, after got one complete request header, before replying succ

        if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->cli_request_handle_time) {
            /* after received header, waiting for proxy and upper layer callback handling */
            return http_con_close(pcon);
        }
    }

starttimer:
    pcon->life_timer = iotimer_start(mgmt->pcore,
                                  mgmt->conn_check_interval * 1000,
                                  t_http_cli_con_life, (void *)pcon->conid,
                                  http_pump, mgmt);
    return 0;
}

