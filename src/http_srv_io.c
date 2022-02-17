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
#include "http_srv_io.h"
#include "http_listen.h"
#include "http_header.h"
#include "http_do.h"
#include "http_response.h"
#include "http_srv.h"
#include "http_proxy.h"
#include "http_cache.h"
#include "http_chunk.h"
#include "http_ssl.h"
#include "http_cookie.h"
#include "http_cc.h"


int http_srv_con_crash (void * vcon, int closelad)
{
    HTTPCon  * srvcon = (HTTPCon *)vcon;
    HTTPMgmt * mgmt = NULL;
    HTTPMsg  * srvmsg = NULL;
    HTTPMsg  * climsg = NULL;
    HTTPCon  * clicon = NULL;
 
    if (!srvcon) return -1;
 
    if (!closelad)
        return http_con_close(srvcon);

    mgmt = (HTTPMgmt *)srvcon->mgmt;
    if (!mgmt) return -2;
 
    srvmsg = http_con_msg_first(srvcon);
    if (!srvmsg)
        return http_con_close(srvcon);
 
    if (srvmsg->proxied == 2 && (climsg = srvmsg->proxymsg)) {
        clicon = http_mgmt_con_get(mgmt, climsg->conid);
        if (clicon)
            http_con_close(clicon);
    }
 
    else if (srvcon->httptunnel && srvcon->tunnelcon) {
        http_con_close(srvcon->tunnelcon);
    }
 
    return http_con_close(srvcon);
}

int http_srv_send_probe (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMsg  * msg = NULL;
    int        num = 0;
 
    if (!pcon) return -1;
 
    if (pcon->snd_state < HTTP_CON_SEND_READY) return -100;
 
    num = arr_num(pcon->msg_list) + http_srv_msg_num(pcon->srv);
    if (num <= 0) {
        if (pcon->snd_state == HTTP_CON_FEEDING)
            pcon->snd_state = HTTP_CON_SEND_READY;
        return 0;
    }
 
    msg = http_con_msg_first(pcon);
    if (msg && (msg->reqsent > 0 || 
                chunk_get_end(msg->req_body_chunk, msg->req_stream_sent,
                              msg->req_body_flag == BC_TE ? 1 : 0)))
    {
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


int http_srv_send (void * vcon) 
{
    HTTPCon     * pcon = (HTTPCon *)vcon;
    HTTPMgmt    * mgmt = NULL;
    HTTPMsg     * msg = NULL;
 
    void        * chunk = NULL;
    chunk_vec_t   iovec;
 
    uint8         httpchunk = 0;
    int           ret = 0;
    int64         filepos = 0;
    int64         bodypos = 0;
    int64         sentnum = 0;
    int           num = 0;
    int           err = 0;
    time_t        curt = 0;
 
    if (!pcon) return -1;
 
    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;
 
    if (pcon->snd_state < HTTP_CON_SEND_READY)
        return -100;
 
    if (pcon->httptunnel && arr_num(pcon->msg_list) <= 0) {
        return http_tunnel_srv_send(pcon->tunnelcon, pcon);
    }

    if (pcon->snd_state == HTTP_CON_FEEDING)
        return 0;
 
    pcon->snd_state = HTTP_CON_FEEDING;
 
    pcon->transact = 1;

    while (arr_num(pcon->msg_list) + http_srv_msg_num(pcon->srv) > 0 &&
           pcon->snd_state == HTTP_CON_FEEDING)
    {
        msg = http_con_msg_first(pcon);
        if (msg) {
            if (msg->conid == 0) {
                msg->conid = pcon->conid;
                msg->pcon = pcon;
            }
 
            if (msg->proxied) {
                httpchunk = 0;
            } else {
                httpchunk = msg->req_body_flag == BC_TE ? 1 : 0;
            }

            /* if HTTPMsg has been sent, just return */
            if (msg->reqsent > 0 || 
                chunk_get_end(msg->req_body_chunk, msg->req_stream_sent, httpchunk))
            {
                pcon->snd_state = HTTP_CON_SEND_READY;
                pcon->transact = 0;

                return 0;
            }

        } else {
            curt = time(0);
            while ((msg = http_srv_msg_pull(pcon->srv)) != NULL) {
                if (curt - msg->createtime > 60) {
                    http_msg_close(msg);
                    msg = NULL;
                    continue;
                }
 
                pcon->msg = msg;
                msg->reqsent = 0;
                msg->req_stream_sent = 0;
 
                http_con_msg_add(pcon, msg);

                if (msg->proxied) {
                    httpchunk = 0;
                } else {
                    httpchunk = msg->req_body_flag == BC_TE ? 1 : 0;
                }

                break;
            }
        }
 
        if (!msg) {
            pcon->snd_state = HTTP_CON_SEND_READY;
            break;
        }
 
        chunk = msg->req_body_chunk;
        filepos = msg->req_stream_sent;
 
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
                http_srv_con_crash(pcon, 1);
                return ret;
            }
 
            if (iovec.size == 0) {
                /* no available data to send, waiting for more data... */
                pcon->snd_state = HTTP_CON_SEND_READY;
                pcon->transact = 0;

                /* all octets in buffer are sent to Origin server and de-congesting process
                   should be started. Connection of client-side is checked to add Read notification
                   if it's removed before */
                http_srv_send_cc(pcon);

                return 0;
            }

            if (iovec.vectype == 2) { //sendfile
                ret = http_con_sendfile(pcon, iovec.filefd, iovec.fpos, iovec.size , &num, &err);
                if (ret < 0) {
                    pcon->snd_state = HTTP_CON_IDLE;
                    http_srv_con_crash(pcon, 1);
                    return ret;
                }
 
            } else if (iovec.vectype == 1) { //mem buffer, writev
                ret = http_con_writev(pcon, iovec.iovs, iovec.iovcnt, &num, &err);
                if (ret < 0) {
                    pcon->snd_state = HTTP_CON_IDLE;
                    http_srv_con_crash(pcon, 1);
                    return ret;
                }
            }
 
            filepos += num;
            sentnum += num;

            if (msg->req_send_procnotify && num > 0 && filepos > msg->req_header_length) {
                bodypos = msg->req_stream_sent - msg->req_header_length;
                if (bodypos <= 0) bodypos = 0;

                (*msg->req_send_procnotify)(msg, msg->req_send_procnotify_para,
                                            msg->req_send_procnotify_cbval,
                                            bodypos, num);
            }
 
            msg->req_stream_sent += num;
 
            http_overhead_sent(pcon->mgmt, num);
            msg->stamp = time(&pcon->stamp);
 
            /* remove the sent ChunkEntity-es in msg->req_body_chunk.
               release the already sent frame objects holding received data from
               client for zero-copy purpose. */
            http_srv_send_final(msg);

#ifdef UNIX
            if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK) { //EAGAIN
#elif defined(_WIN32) || defined(_WIN64)
            if (err == WSAEWOULDBLOCK) {
#else
            if (num == 0) {
#endif
                pcon->snd_state = HTTP_CON_SEND_READY;
                pcon->transact = 0;

                iodev_add_notify(pcon->pdev, RWF_WRITE);

                /* all octets in buffer are sent to Origin server and de-congesting process
                   should be started. Connection of client-side is checked to add Read notification
                   if it's removed before */
                http_srv_send_cc(pcon);

                return 0;
            }
        }
 
        if (pcon->srv) time(&((HTTPSrv *)(pcon->srv))->stamp);

        if (chunk_get_end(chunk, msg->req_stream_sent, httpchunk) == 1) {
            /* do not send any ohter httpmsg, just wait for the response after sending request */
            msg->reqsent = 1;
            pcon->reqnum++;

            /* should not send other HTTPMsg before got the response */
            pcon->snd_state = HTTP_CON_SEND_READY;
            pcon->transact = 0;

            return 0;
        }
 
    } //end while
 
    pcon->snd_state = HTTP_CON_SEND_READY;

    if (arr_num(pcon->msg_list) <= 0) {
        /* the connection has no msg sent or to be sent, now set to idle */
        pcon->transact = 0;
    }
 
    /* HTTPRequest has been sent to server, now the current HTTPCon should not send 
     * anything anymore before receiving the response.  */
 
    return 0;
}

int http_srv_send_final (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    frame_p    frm = NULL;
    int        i, num;
    int        fnum = 0;
 
    if (!msg) return -1;
 
    fnum = chunk_remove(msg->req_body_chunk, msg->req_stream_sent, 0);
    if (fnum <= 0)
        return 0;
 
    num = arr_num(msg->req_rcvs_list);
    for (i = 0; i < num; i++) {
        frm = arr_value(msg->req_rcvs_list, i);
 
        fnum = chunk_bufptr_porig_find(msg->req_body_chunk, frm);
        if (fnum <= 0) {
            arr_delete(msg->req_rcvs_list, i);
            frame_free(frm);
            i--; num--;
        }
    }

    return 0;
}


int http_srv_recv (void * vcon)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
    HTTPMgmt   * mgmt = NULL;
    HTTPMsg    * msg = NULL;
    int          ret = 0, num = 0;
    int          err = 0;
    uint8        crashed = 0;
    int          times = 0;

    if (!pcon) return -1;

    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;

    /* If the receiving speed of server side is greater than the sending
       speed of client side, a great deal of data will be piled up in memory.
       Congestion control should be activated by neglecting the read-ready event.
       After that, receving buffer of underlying TCP will be full soon.
       TCP stack will start congestion control mechanism */
    if (http_srv_recv_cc(pcon) > 0)
        return 0;

    while (1) {

        crashed = 0;

        ret = http_con_read(pcon, pcon->rcvstream, &num, &err);
        if (ret < 0) {
            crashed = 1;

            if (pcon->snd_state == HTTP_CON_CONNECTING &&
                time(0) - pcon->stamp > 6)
            {
                http_srv_set_active(pcon->srv, 0);
            }

            if (frameL(pcon->rcvstream) <= 0) {
                http_srv_con_crash(pcon, 1);
                return -100;
            }
        }

        time(&pcon->stamp);
        if (pcon->read_ignored > 0)
            pcon->read_ignored = 0;

        if (num > 0) http_overhead_recv(mgmt, num);
 
        if (pcon->srv)
            time(&((HTTPSrv *)(pcon->srv))->stamp);

        if (pcon->httptunnel) {
            times = 0;
            while (frameL(pcon->rcvstream) > 0 && times++ < 6) {
                ret = http_tunnel_cli_send(pcon, pcon->tunnelcon);
                if (ret < 0) {
                   http_con_close(pcon->tunnelcon);
                   http_con_close(pcon);
                   break;
                }
            }

            if (crashed) {
               http_con_close(pcon->tunnelcon);
               http_con_close(pcon);
            }

            return 0;
        }

        ret = http_srv_recv_parse(pcon);
        if (ret < 0) {
            http_srv_con_crash(pcon, 1);
            return ret;

        } else if (ret == 0) {
            if (crashed)
                http_srv_con_crash(pcon, 1);

            return 0;

        } else {
            /* the HTTP Request sent and its Response received successfully.
               HTTPCon should be reused to send the next Request queued in FIFO.  */

            pcon->msg = NULL;
            pcon->rcv_state = HTTP_CON_READY;

            msg = http_con_msg_first(pcon);
            http_con_msg_del(pcon, msg);

            if (msg != NULL) {
                if (msg->res_status == 301 || msg->res_status == 302) {
                    if (http_redirect_request(msg) >= 0)
                        return 0;
                }

                if (msg->resnotify && !msg->resnotify_called) {
                    (*msg->resnotify)(msg, msg->resnotify_para, msg->resnotify_cbval, msg->res_status);
                    msg->resnotify_called = 1;
                }

                http_msg_close(msg);
            }

            if (frameL(pcon->rcvstream) <= 0) {
                /* HTTPCon finished request/response sending and recving, now set it to idle state */
                pcon->transact = 0;

                /* go on sending another HTTPRequest and receiving its Response */
                if (arr_num(pcon->msg_list) + http_srv_msg_num(pcon->srv) > 0) {
                    http_srv_send(pcon);
                }

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
 *    1 : complete HTTP-Response with body data parsed successfully
 *    2 : complete HTTP-Response without body data parsed successfully */
int http_srv_recv_parse (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPCon  * clicon = NULL;
    HTTPMsg  * msg = NULL;
    HTTPMgmt * mgmt = NULL;
    HTTPMsg  * proxymsg = NULL;
    int        resend = 0;
    int        ret = 0;
    long       num = 0;
    int64      hdrlen = 0;
    uint8    * pbyte = NULL;
    uint8    * pbgn = NULL;

    int64      saveoffset = 0;
    int64      savedbytes = 0;
 
    if (!pcon) return -1;
 
    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;
 
    num = frameL(pcon->rcvstream);
    if (num <= 0) {
        return 0;
    }
 
    if (pcon->rcv_state == HTTP_CON_WAITING_BODY) {
        msg = http_con_msg_first(pcon);
        if (!msg) {
            return -101;
        }
 
        msg->stamp = time(0);

        if (msg->proxied && msg->proxymsg) {
            proxymsg = msg->proxymsg;

            if (proxymsg->req_url_type == 0 && 
                (msg->res_status == 301 || msg->res_status == 302) &&
                mgmt->auto_redirect)
            {
                /* it's a reverse proxy, redirect response should be handled by issuing
                   new url instead of replying directly. the response body must be deleted. */

                ret = http_proxy_srvbody_del(pcon, msg);
                if (ret < 0) {
                    http_con_close(pcon);
                    http_con_close(proxymsg->pcon);
                    return -200;

                } else if (ret == 0) {
                    pcon->rcv_state = HTTP_CON_WAITING_BODY;
                    return 0;
                }

                pcon->rcv_state = HTTP_CON_READY;
 
                if (http_redirect_request(msg) >= 0) {
                    return 0;
                }
            }

            if (proxymsg->cacheon/* && proxymsg->res_cache_info*/)
                http_proxy_srv_cache_store(pcon, msg);
            else
                http_proxy_cli_send(proxymsg->pcon, proxymsg);

            return 0;
        }

        switch (msg->res_body_flag) {

        case BC_CONTENT_LENGTH:
        case BC_TE:

            ret = http_srv_resbody_parse(pcon, msg, &saveoffset, &savedbytes);
            if (ret < 0) {
                return -102;

            } else if (ret == 0) { //waiting more body
                pcon->rcv_state = HTTP_CON_WAITING_BODY;

            } else {
                pcon->rcv_state = HTTP_CON_READY;
            }

            if (savedbytes > 0 && msg->res_recv_procnotify)
                (*msg->res_recv_procnotify)(msg, msg->res_recv_procnotify_para,
                                            msg->res_recv_procnotify_cbval,
                                            saveoffset, savedbytes);


            return ret;
 
        default:
            return -103;
        }

    } else {
        pbgn = frameP(pcon->rcvstream);
 
        /* determine if http header got completely */
        pbyte = kmp_find_bytes(pbgn, num, "\r\n\r\n", 4, NULL);
        if (!pbyte) {
            if (num > mgmt->srv_max_header_size) {
                /* request header is too large, possibly a malicious attack */
                return -104;
            }
            pcon->rcv_state = HTTP_CON_WAITING_HEADER;
 
            return 0;
        }
        hdrlen = pbyte + 4 - pbgn;
 
        msg = http_con_msg_first(pcon);
        if (!msg) return -105;

        pcon->resnum++;
        msg->stamp = time(0);
        msg->state = HTTP_MSG_REQUEST_RECVING;
        msg->res_header_length = hdrlen;
        msg->res_stream_recv += hdrlen;

        if (hdrlen > 0) {
            /* remove the last 2 trailer "\r\n" */
            frame_put_nlast(msg->res_header_stream, pbgn, hdrlen - 2);
            frame_del_first(pcon->rcvstream, hdrlen);
        }

        ret = http_res_parse_header(msg, 1);
        if (ret < 0) return -106;
 
        pcon->keepalive = msg->res_conn_keepalive;
 
        /* if the msg is proxied for client, duplicates response header into
           client msg, and divert body to client */

        if (msg->proxied && msg->proxymsg) {
            proxymsg = msg->proxymsg;

            /* req_url_type represents client URL is relative(0) or absolute(1).
               relative URL(0) plus proxied flag indicates it acts as reverse proxy.
               absolute URL(1) plus proxied flag indicates it's a forward proxy */

            if (proxymsg->req_url_type == 0 &&
                (msg->res_status == 301 || msg->res_status == 302) &&
                mgmt->auto_redirect)
            {
                /* for reverse proxy, current server must handle redirect for the client automatically.
                   the response body must be removed before redirecting */
                ret = http_proxy_srvbody_del(pcon, msg);
                if (ret < 0) { 
                    http_con_close(pcon);
                    http_con_close(proxymsg->pcon);
                    return -200;

                } else if (ret == 0) {
                    pcon->rcv_state = HTTP_CON_WAITING_BODY;
                    return 0;
                }
                pcon->rcv_state = HTTP_CON_READY;

                /* parse the Set-Cookie header and store the Cookies into local storage */
                http_set_cookie_parse(msg);

                if (http_redirect_request(msg) >= 0) {
                    return 0;
                }
            }

            if (msg->cacheon) {
                http_proxy_cache_parse(msg, proxymsg, &resend);
                if (msg->cacheon <= 0 && resend > 0) {
                    /* the response indicates no cache or no store. the requested
                       range is not original content, now resend original request again. */
                    proxymsg->proxymsg = NULL;

                    http_con_msg_del(pcon, msg);
                    http_msg_close(msg);
                    http_con_close(pcon);

                    http_proxy_srv_cache_send(proxymsg);
                    return 0;
                }
            }

            http_proxy_climsg_dup(msg);

            /* bind srvcon and clicon, the events of two HTTPCon are handled in one thread */
            clicon = proxymsg->pcon;
            if (clicon) iodev_workerid_set(pcon->pdev, iodev_workerid(clicon->pdev));

            if (proxymsg->cacheon && proxymsg->res_cache_info)
                http_proxy_srv_cache_store(pcon, msg);
            else
                http_proxy_cli_send(proxymsg->pcon, proxymsg);

            return 0;
        }

        /* parse the Set-Cookie header and store the Cookies into local storage */
        http_set_cookie_parse(msg);

        switch (msg->res_body_flag) {

        case BC_CONTENT_LENGTH:
        case BC_TE:

            ret = http_srv_resbody_parse(pcon, msg, &saveoffset, &savedbytes);
            if (ret < 0) {
                return -107;

            } else if (ret == 0) { //waiting more body
                pcon->rcv_state = HTTP_CON_WAITING_BODY;

            } else {
                pcon->rcv_state = HTTP_CON_READY;
            }

            if (savedbytes > 0 && msg->res_recv_procnotify)
                (*msg->res_recv_procnotify)(msg, msg->res_recv_procnotify_para,
                                            msg->res_recv_procnotify_cbval,
                                            saveoffset, savedbytes);


            return ret;
 
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
    }
 
    return 0;
}
 
 
int http_srv_resbody_parse (void * vcon, void * vmsg, int64 * offset, int64 * savedbytes)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    char     * pbody = NULL;
    int        bodylen = 0;
    int64      restlen = 0;
    int        ret, rmlen = 0;
 
    if (offset) *offset = 0;
    if (savedbytes) *savedbytes = 0;

    if (!pcon) return -1;
    if (!msg) return -2;
 
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -3;
 
    pbody = frameP(pcon->rcvstream);
    bodylen = frameL(pcon->rcvstream);
 
    switch (msg->res_body_flag) {
 
    case BC_CONTENT_LENGTH:
 
        restlen = msg->res_body_length - msg->res_body_iolen;
        if (bodylen >= restlen)
            bodylen = restlen;
 
        if (!msg->res_file_handle) {
            http_response_cache_init(msg);
 
            if (msg->res_file_handle) {
                frame_filefd_write(msg->res_body_stream, native_file_fd(msg->res_file_handle), 0);
                frame_empty(msg->res_body_stream);
            }
        }
 
        if (msg->res_file_cache && msg->res_file_handle) {
            native_file_write(msg->res_file_handle, pbody, bodylen);
 
        } else {
            frame_put_nlast(msg->res_body_stream, pbody, bodylen);
        }
 
        if (offset) *offset = msg->res_body_iolen;
        if (savedbytes) *savedbytes = bodylen;

        frame_del_first(pcon->rcvstream, bodylen);
        msg->res_body_iolen += bodylen;
        msg->res_stream_recv += bodylen;
 
        if (msg->res_body_iolen >= msg->res_body_length) {
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
        if (http_chunk_gotall(msg->res_chunk))
            return 1;
 
        ret = http_chunk_add_bufptr(msg->res_chunk, pbody, bodylen, &rmlen);
        if (ret < 0) return -30;
 
        restlen = chunk_rest_size(http_chunk_obj(msg->res_chunk), 0);

        if (offset) *offset = msg->res_body_iolen;
        if (savedbytes) *savedbytes = restlen;

        msg->res_body_iolen += restlen;
        msg->res_body_length += restlen;
 
        if (!msg->res_file_handle) {
            http_response_cache_init(msg);
 
            if (msg->res_file_handle) {
                frame_filefd_write(msg->res_body_stream, native_file_fd(msg->res_file_handle), 0);
                frame_empty(msg->res_body_stream);
            }
        }
 
        if (msg->res_file_handle) {
            chunk_readto_file(http_chunk_obj(msg->res_chunk), native_file_fd(msg->res_file_handle), 0, -1, 0);
 
        } else {
            chunk_readto_frame(http_chunk_obj(msg->res_chunk), msg->res_body_stream, 0, -1, 0);
        }
 
        chunk_remove(http_chunk_obj(msg->res_chunk), msg->res_body_length, 0);
 
        msg->res_stream_recv += rmlen;
        if (rmlen > 0)
            frame_del_first(pcon->rcvstream, rmlen);
 
        if (http_chunk_gotall(msg->res_chunk)) {
            goto gotallbody;
        }
 
        return 0;
 
    default:
        return -10;
    }
 
    return 0;
 
gotallbody:
 
    if (msg->res_file_handle) {
        chunk_add_filefd(msg->res_body_chunk,
                         native_file_fd(msg->res_file_handle),
                         0, -1);
    } else {
        chunk_add_bufptr(msg->res_body_chunk,
                         frameP(msg->res_body_stream),
                         frameL(msg->res_body_stream), NULL, NULL);
    }

    return 1;
}

int http_srv_con_lifecheck (void * vcon)
{
    HTTPCon  * pcon = (HTTPCon *)vcon;
    HTTPMgmt * mgmt = NULL;
    HTTPMsg  * msg = NULL;
    time_t     curt = 0;
    int        num = 0;

    if (!pcon) return -1;

    mgmt = (HTTPMgmt *)pcon->mgmt;
    if (!mgmt) return -2;

    num = arr_num(pcon->msg_list) + http_srv_msg_num(pcon->srv);
    time(&curt);

    if (pcon->httptunnel) {
        if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->tunnel_keepalive_time) {
            return http_srv_con_crash(pcon, 1);
        }
        goto starttimer;
    }

    if (num <= 0 && curt - pcon->stamp >= mgmt->srv_keepalive_time) {
        /* keep the connection alive for sending new coming httpmsg. */
        return http_con_close(pcon);
    }

    if (pcon->snd_state < HTTP_CON_SEND_READY && curt - pcon->stamp >= mgmt->srv_connecting_time) {
        /* if exceeds the max time that builds TCP connection to remote server, close it.
           seems that it never go here */
        return http_srv_con_crash(pcon, 1);
    }

    if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->srv_conn_idle_time) {
        /* when sending or receiving, the TCP connection is in idle that
           there is not any I/O operations occurring.
           e.g. long-polling connection to server can exist for conn_idle_time */
        return http_srv_con_crash(pcon, 1);
    }

    if (num > 0 && pcon->snd_state == HTTP_CON_SEND_READY && pcon->rcv_state == HTTP_CON_READY) {
        /* HTTPCon sending and receivng facilities are in ready state */

        msg = http_con_msg_first(pcon);
        if (msg && msg->proxied == 2) {
            /* proxy msg is driven by client request, periodic timer does not trigger sending.
               here do nothing */

        } else {
            http_srv_send_probe(pcon);
        }
    }

starttimer:
    pcon->life_timer = iotimer_start(mgmt->pcore,
                                  mgmt->conn_check_interval * 1000,
                                  t_http_srv_con_life, (void *)pcon->conid,
                                  http_pump, mgmt);

    return 0;
}

