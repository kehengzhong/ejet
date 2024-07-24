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
#include "http_chunk.h"
#include "http_header.h"
#include "http_request.h"
#include "http_response.h"
#include "http_cli_io.h"
#include "http_cc.h"

#include "http_fcgi_srv.h"
#include "http_fcgi_msg.h"
#include "http_fcgi_con.h"
#include "http_fcgi_io.h"

extern HTTPMgmt * gp_httpmgmt;

int http_fcgi_send_probe (void * vsrv, ulong conid)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = NULL;
    FcgiMsg  * msg = NULL;
    int        num = 0;
 
    if (!srv) return -1;

    pcon = http_fcgisrv_con_get(srv, conid);
    if (!pcon) return -2;

    if (pcon->snd_state < FCGI_CON_SEND_READY) return -100;
 
    num = arr_num(pcon->msg_list) + http_fcgisrv_msg_num(pcon->srv);
    if (num <= 0) {
        if (pcon->snd_state == FCGI_CON_FEEDING)
            pcon->snd_state = FCGI_CON_SEND_READY;

        return 0;
    }
 
    msg = http_fcgicon_msg_first(pcon);
    if (msg && (msg->reqsent > 0 || 
                chunk_get_end(msg->req_body_chunk, msg->req_stream_sent, 0)))
    {
        if (pcon->snd_state == FCGI_CON_FEEDING)
            pcon->snd_state = FCGI_CON_SEND_READY;
 
        return 0;
    }
 
    if (pcon->snd_state == FCGI_CON_FEEDING) {
        return 0;
    }
 
    iodev_add_notify(pcon->pdev, RWF_WRITE);
 
    return 0;
}

int http_fcgi_send (void * vsrv, ulong conid)
{
    FcgiSrv     * srv = (FcgiSrv *)vsrv;
    FcgiCon     * pcon = NULL;
    FcgiMsg     * msg = NULL;
    time_t        curt = 0;

    void        * chunk = NULL;
    chunk_vec_t   iovec;
 
    int           ret = 0;
    int64         filepos = 0;
    int64         sentnum = 0;
    int           num = 0;
    int           err = 0;

    if (!srv) return -1;

    pcon = http_fcgisrv_con_get(srv, conid);
    if (!pcon) return -2;

    if (pcon->snd_state < FCGI_CON_SEND_READY)
        return -100;
 
    if (pcon->snd_state == FCGI_CON_FEEDING)
        return 0;
 
    pcon->snd_state = FCGI_CON_FEEDING;

    while (arr_num(pcon->msg_list) + http_fcgisrv_msg_num(pcon->srv) > 0 &&
           pcon->snd_state == FCGI_CON_FEEDING)
    {
        msg = http_fcgicon_msg_first(pcon);
        if (msg) {
 
            if (msg->conid == 0) {
                msg->conid = pcon->conid;
                msg->pcon = pcon;
            }
 
            /* if FcgiMsg has been sent, just return */
            if (msg->reqsent > 0 || 
                chunk_get_end(msg->req_body_chunk, msg->req_stream_sent, 0))
            {
                pcon->snd_state = FCGI_CON_SEND_READY;
                return 0;
            }

        } else {
            curt = time(0);
            while ((msg = http_fcgisrv_msg_pull(pcon->srv)) != NULL) {
                if (curt - msg->createtime.s > 60) {
                    http_fcgimsg_close(msg);
                    msg = NULL;
                    continue;
                }
 
                pcon->msg = msg;
                msg->reqsent = 0;
                msg->req_stream_sent = 0;
 
                http_fcgicon_msg_add(pcon, msg);
                break;
            }
        }

        if (!msg) {
            pcon->snd_state = FCGI_CON_SEND_READY;
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

        for (sentnum = 0; chunk_get_end(chunk, filepos, 0) == 0; ) {
 
            memset(&iovec, 0, sizeof(iovec));
            ret = chunk_vec_get(chunk, filepos, &iovec, 0);

            if (ret < 0 || (iovec.size > 0 && iovec.vectype != 1 && iovec.vectype != 2)) {
                pcon->snd_state = FCGI_CON_IDLE;
                http_fcgicon_crash_handle(srv, conid);
                return ret;
            }
 
            if (iovec.size == 0) {
                /* no available data to send, waiting for more data... */
                pcon->snd_state = FCGI_CON_SEND_READY;

                /* all octets in buffer are sent to FastCGI server and de-congesting process
                   should be started. Connection of client-side is checked to add Read notification
                   if it's removed before */
                http_fcgi_send_cc(srv, conid);

                return 0;
            }
 
            if (iovec.vectype == 2) { //sendfile
                ret = tcp_sendfile(iodev_fd(pcon->pdev), iovec.filefd,
                                   iovec.fpos, iovec.size , &num, &err);
                if (ret < 0) {
                    pcon->snd_state = FCGI_CON_IDLE;
                    http_fcgicon_crash_handle(srv, conid);
                    return ret;
                }
 
            } else if (iovec.vectype == 1) { //mem buffer, writev
                ret = tcp_writev(iodev_fd(pcon->pdev), iovec.iovs, iovec.iovcnt, &num, &err);
                if (ret < 0) {
                    pcon->snd_state = FCGI_CON_IDLE;
                    http_fcgicon_crash_handle(srv, conid);
                    return ret;
                }
            }
 
            filepos += num;
            msg->req_stream_sent += num;
            sentnum += num;
            msg->stamp = time(&pcon->stamp);
 
            /* remove the sent ChunkEntity-es in msg->req_body_chunk.
               release the already sent frame objects holding received data from
               client for zero-copy purpose. */
            http_fcgi_send_final(msg);

#ifdef UNIX
            if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK) { //EAGAIN
#elif defined(_WIN32) || defined(_WIN64)
            if (err == WSAEWOULDBLOCK) {
#else
            if (num == 0) {
#endif
                pcon->snd_state = FCGI_CON_SEND_READY;
                iodev_add_notify(pcon->pdev, RWF_WRITE);

                /* all octets in buffer are sent to FastCGI server and de-congesting process
                   should be started. Connection of client-side is checked to add Read notification
                   if it's removed before */
                if (sentnum > 0)
                    http_fcgi_send_cc(srv, conid);

                return 0;
            }
        }

        if (pcon->srv) time(&((FcgiSrv *)(pcon->srv))->stamp);
 
        if (chunk_get_end(chunk, msg->req_stream_sent, 0) == 1) {
            /* do not send any other fcgimsg, just wait for the response after sending request */
            msg->reqsent = 1;
            pcon->reqnum++;
 
            /* should not send other HTTPMsg before got the response */
            pcon->snd_state = FCGI_CON_SEND_READY;
            return 0;
        }
    } //end while

    pcon->snd_state = FCGI_CON_SEND_READY;

    return 0;
}

int http_fcgi_send_final (void * vmsg)
{
    FcgiMsg  * msg = (FcgiMsg *)vmsg;
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
 
    return 1;
}


int http_fcgicon_crash_handle_dbg (void * vsrv, ulong conid, char * file, int line)
{
    FcgiSrv * srv = (FcgiSrv *)vsrv;
    FcgiCon * pcon = NULL;
    FcgiMsg * msg = NULL;
    HTTPMsg * httpmsg = NULL;

    if (!srv) return -1;

    pcon = http_fcgisrv_con_get(srv, conid);
    if (!pcon) return -2;

    msg = http_fcgicon_msg_first(pcon);
 
    if (msg && (httpmsg = msg->httpmsg)) {
        if (!msg->got_all_header && httpmsg->fcgi_resend < 3) {
            frame_empty(httpmsg->res_header_stream);
            http_fcgi_send_start(pcon->srv, httpmsg);
 
            http_fcgicon_close_dbg(srv, conid, file, line);
            return 0;
        }
    }
 
    http_fcgimsg_pre_crash(msg, 503);
    http_fcgicon_close_dbg(srv, conid, file, line);
 
    return -100;
}


int http_fcgi_recv (void * vsrv, ulong conid)
{
    FcgiSrv * srv = (FcgiSrv *)vsrv;
    FcgiCon * pcon = NULL;
    FcgiMsg * msg = NULL;
    int       ret = 0, num = 0;
    int       err = 0;
    uint8     crashed = 0;
 
    if (!srv) return -1;
 
    pcon = http_fcgisrv_con_get(srv, conid);
    if (!pcon) return -2;

    /* If the receiving speed of FastCGI server is greater than the sending
       speed of client side, a great deal of data will be piled up in memory.
       Congestion control should be activated by neglecting the read-ready event of server side.
       After that, receving buffer of underlying TCP/UnixSocket will be full soon.
       TCP/UnixSocket stack will start congestion control mechanism */
    if (http_fcgi_recv_cc(srv, conid) > 0) 
        return 0;

    while (1) {
 
        crashed = 0;
 
        ret = frame_tcp_nbzc_recv(pcon->rcvstream, iodev_fd(pcon->pdev), &num, &err);
        if (ret < 0) {
            crashed = 1;
 
            if (frameL(pcon->rcvstream) <= 0) {
                return http_fcgicon_crash_handle(srv, conid);
            }
        }
 
        time(&pcon->stamp);
        if (pcon->read_ignored > 0)
            pcon->read_ignored = 0;
 
        if (pcon->srv)
            time(&((FcgiSrv *)(pcon->srv))->stamp);
 
        if (frameL(pcon->rcvstream) <= 0) 
           return 0;

        //ret = http_fcgi_recv_parse(pcon);
        ret = http_fcgi_recv_forward(srv, conid);
        if (ret < 0) {
            return http_fcgicon_crash_handle(srv, conid);
 
        } else if (ret == 0) {
            if (crashed) {
                http_fcgicon_crash_handle(srv, conid);
            }
 
            return 0;
 
        } else {
            /* the HTTP Request transformed into FCGI_Request and sent it.
               FCGI Response received successfully also.
               FcgiCon should be reused to send the next Request queued in FIFO.  */
 
            pcon->msg = NULL;
            pcon->rcv_state = FCGI_CON_READY;
 
            msg = http_fcgicon_msg_first(pcon);
            http_fcgicon_msg_del(pcon, msg);
 
            if (msg != NULL) {
                http_fcgimsg_close(msg);
            }
 
            if (frameL(pcon->rcvstream) <= 0) {
                /* go on sending another Fcgi Request and receiving its Response */
                if (arr_num(pcon->msg_list) + http_fcgisrv_msg_num(pcon->srv) > 0) {
                    http_fcgi_send(srv, conid);
                }
 
                return 0;
            }
        }
 
    } //end while (1)
 
    return 0;
}

/* move the octets of header of STDOUT from FCGI-Server to HTTPMsg res_header_stream
   move the octets of body of STDOUT to HTTPMsg res_body_stream
   when encountering END_REQUESt, all body got and reply HTTPMsg to client */

int http_fcgi_recv_parse (void * vcon)
{
    FcgiCon  * pcon = (FcgiCon *)vcon;
    FcgiMsg  * msg = NULL;
    FcgiSrv  * srv = NULL;

    HTTPMgmt * mgmt = NULL;
    HTTPMsg  * httpmsg = NULL;

    uint8    * pbgn = NULL;
    uint8    * pbody = NULL;
    uint8    * pbyte = NULL;
    uint8    * pend  = NULL;
    int        num = 0;

    int        iter = 0;
    int        hdrlen = 0;
    int        bodylen = 0;
    int        padding = 0;

    uint8    * ppar[4];
    int        arlen[4];
    int        ind = 0;
    int        ret = 0;

    if (!pcon) return -1;

    srv = (FcgiSrv *)pcon->srv;
    if (!srv) return -2;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return -3;

    num = frameL(pcon->rcvstream);
    if (num <= 0) {
        return 0;
    }

    msg = http_fcgicon_msg_first(pcon);
    if (!msg) {  //the FCGI Response has no corresponding FCGI request
        return -102;
    }

    httpmsg = msg->httpmsg;
    if (!httpmsg) return -103;

    if (httpmsg->res_header_stream == NULL)
        httpmsg->res_header_stream = frame_alloc(0, httpmsg->alloctype, httpmsg->kmemblk);

    while ((num = frameL(pcon->rcvstream)) >= 8) {
        pbgn = frameP(pcon->rcvstream);

        hdrlen = fcgi_header_decode(pbgn, num, &msg->cgihdr);
        if (hdrlen != 8)  //FcgiHeader length
            return 0;

        if (!fcgi_header_type_valid(msg->cgihdr.type, 1)) { //if FCGI type invalid
            return -101;
        }

        pbody = pbgn + hdrlen;
        bodylen = msg->cgihdr.contlen;
        padding = msg->cgihdr.padding;
        pend = pbody + bodylen;

        if (msg->cgihdr.type == FCGI_STDOUT) {
            if (bodylen == 0) {
                /* FCGI response body got end */
                frame_del_first(pcon->rcvstream, hdrlen);
                continue;
            }

            if (hdrlen + bodylen > num) {
                /* there is no more data to fill one complete FCGI Pdu */
                return 0;  //waiting for more data coming
            }

            ppar[0]  = frameP(httpmsg->res_header_stream);
            arlen[0] = frameL(httpmsg->res_header_stream);
            ppar[1]  = pbody;
            arlen[1] = bodylen;

            if (msg->got_all_header == 0) {

                pbyte = sun_find_mbytes((void **)ppar, arlen, 2,  "\r\n\r\n", 4, NULL, &ind);
                if (!pbyte) {
                    if (arlen[0] + arlen[1] > mgmt->srv_max_header_size) {
                        /* request header is too large, possibly a malicious attack */
                        return -104;
                    }
    
                    msg->got_all_header = 0;

                    frame_put_nlast(httpmsg->res_header_stream, pbody, bodylen);
                    frame_del_first(pcon->rcvstream, pend - pbgn + padding);

                    continue;
                }
    
                msg->got_all_header = 1;

                if (ind == 0) { /* \r\n\r\n occurs in res_header_stream */

                    if (pbyte + 4 <= ppar[0] + arlen[0]) {
                        /* there are some body octets retained in res_header_stream, 
                           move them to body_stream */
                        iter = ppar[0] + arlen[0] - pbyte - 4;
                        if (iter > 0) {
                            frame_put_nlast(httpmsg->res_body_stream, pbyte + 4, iter);
                            frame_del_last(httpmsg->res_body_stream, iter);
                        }

                        /* move all STDOUT body into httpmsg->res_body_stream */
                        frame_put_nlast(httpmsg->res_body_stream, pbody, bodylen);

                    } else {
                        /* header trailer \r\n\r\n across the 2 buffer, move them 
                           into httpmsg->res_header_stream */
                        iter = pbyte + 4 - ppar[0] - arlen[0];
                        frame_put_nlast(httpmsg->res_header_stream, pbody, iter);

                        /* move STDOUT body into httpmsg->res_body_stream */
                        frame_put_nlast(httpmsg->res_body_stream, pbody + iter, bodylen - iter);
                    }

                    /* remove the octets of first FastCGI pdu */
                    frame_del_first(pcon->rcvstream, pend - pbgn + padding);

                } else if (ind == 1) {
                    iter = pbyte + 4 - pbody;
                    frame_put_nlast(httpmsg->res_header_stream, pbody, iter);

                    /* move STDOUT body into httpmsg->res_body_stream */
                    frame_put_nlast(httpmsg->res_body_stream, pbody + iter, pend - pbody - iter);

                    /* remove the octets of first FastCGI pdu */
                    frame_del_first(pcon->rcvstream, pend - pbgn + padding);
                }
    
                ret = http_res_parse_header(httpmsg, 0);
                if (ret < 0) return -106;
    
                continue;

            } else {  //STDOUT header has been got before
                /* move STDOUT body into httpmsg->res_body_stream */
                frame_put_nlast(httpmsg->res_body_stream, pbody, bodylen);

                /* remove the octets of first FastCGI pdu */
                frame_del_first(pcon->rcvstream, pend - pbgn + padding);

                continue;
            }

        } else if (msg->cgihdr.type == FCGI_END_REQUEST) {
            if (bodylen != 8) {
            }

            msg->app_status = (pbody[0] << 24) + (pbody[1] << 16) + (pbody[2] << 8) + pbody[3];
            msg->proto_status = pbody[4];

            /* remove the octets of unknown FastCGI pdu */
            frame_del_first(pcon->rcvstream, pend - pbgn + padding);

            msg->got_end_request = 1;

            if ((bodylen = frameL(httpmsg->res_body_stream)) > 0) {
                chunk_add_bufptr(httpmsg->res_body_chunk, frameP(httpmsg->res_body_stream),
                                 bodylen, NULL, NULL);
            }

            if (msg->proto_status != 0) {
                httpmsg->SetStatus(httpmsg, 406, NULL);
            } else {
                httpmsg->SetStatus(httpmsg, 200, NULL);
            }

            /* clear the possible remaining octets in FcgiCon rcvstream */
            frame_empty(pcon->rcvstream);

            /* FcgiMsg has done all job, now unbind it from FcgiCon */
            pcon->msg = NULL;
            http_fcgicon_msg_del(pcon, msg);

            /* close FcgiMsg */
            http_fcgimsg_close(msg);

            /* unset httpmsg's fcgimsg value */
            httpmsg->fcgimsg = NULL;

            /* extracted data from FcgiCon/FcgiMsg to HTTP response successfully!
               now send the HTTP response to client */ 

            return httpmsg->Reply(httpmsg);

        } else if (msg->cgihdr.type == FCGI_STDERR) {
            /* remove the octets of unknown FastCGI pdu */
            frame_del_first(pcon->rcvstream, pend - pbgn + padding);

        } else {
            /* remove the octets of unknown FastCGI pdu */
            frame_del_first(pcon->rcvstream, pend - pbgn + padding);
        }
    } //end while

    return 0;
}

/* First, we must get header octets for assembly a new HTTP response headers.
   Then, send header and body octets directly to client as soon as receiving any data */

int http_fcgi_recv_forward (void * vsrv, ulong conid)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = NULL;
    FcgiMsg  * msg = NULL;
    frame_p    frm = NULL;

    HTTPMgmt * mgmt = NULL;
    HTTPMsg  * httpmsg = NULL;
    HeaderUnit * punit = NULL;

    uint8    * pbgn = NULL;
    uint8    * pbody = NULL;
    uint8    * pbyte = NULL;
    uint8    * pbodyend  = NULL;
    uint8    * pend  = NULL;
    int        num = 0;
    char       sbuf[128];
    int        status = 200;

    int        iter = 0;
    int        hdrlen = 0;
    int        bodylen = 0;
    int        padding = 0;

    uint8    * ppar[4];
    int        arlen[4];
    int        ind = 0;
    int        ret = 0;
    int        len = 0;

    if (!srv) return -1;

    pcon = http_fcgisrv_con_get(srv, conid);
    if (!pcon) return -2;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return -3;

    num = frameL(pcon->rcvstream);
    if (num <= 0) {
        return 0;
    }

    msg = http_fcgicon_msg_first(pcon);
    if (!msg) {  //the FCGI Response has no corresponding FCGI request
        return -102;
    }

    httpmsg = msg->httpmsg;
    if (!httpmsg) return -103;

    EnterCriticalSection(&pcon->excCS);
    frm = pcon->rcvstream;
    arr_push(httpmsg->res_rcvs_list, frm);
    pcon->rcvstream = frame_alloc(0, pcon->alloctype, pcon->kmemblk);
    LeaveCriticalSection(&pcon->excCS);
 
    pbgn = frameP(frm);
    num = frameL(frm);
    iter = 0;

    if (httpmsg->res_header_stream == NULL)
        httpmsg->res_header_stream = frame_alloc(0, httpmsg->alloctype, httpmsg->kmemblk);

    while (iter + 8 <= num) { 
        if (!msg->cgihdr.wait_more_data) {
            memset(&msg->cgihdr, 0, sizeof(msg->cgihdr));

            hdrlen = fcgi_header_decode(pbgn + iter, num - iter, &msg->cgihdr);
            if (hdrlen != 8)  //FcgiHeader length
                return 0;
    
            if (!fcgi_header_type_valid(msg->cgihdr.type, 1)) { //if FCGI type invalid
                return -101;
            }
    
            msg->cgihdr.body_to_read = msg->cgihdr.contlen;
            msg->cgihdr.padding_to_read = msg->cgihdr.padding;

            pbody = pbgn + iter + hdrlen;
            pbodyend = pbody + msg->cgihdr.contlen;
            pend = pbodyend + msg->cgihdr.padding;

        } else {
            pbody = pbgn + iter;
            pbodyend = pbody + msg->cgihdr.body_to_read;
            pend = pbodyend + msg->cgihdr.padding_to_read;
        }

        if (pend > pbgn + num) {
            msg->cgihdr.wait_more_data = 1;
            msg->cgihdr.data_to_read = pend - pbgn - num;

            pend = pbgn + num;

            if (pbodyend > pbgn + num)
                pbodyend = pbgn + num;

        } else {
            msg->cgihdr.wait_more_data = 0;
        }
    
        bodylen = pbodyend - pbody;
        if (bodylen < msg->cgihdr.body_to_read) {
            msg->cgihdr.body_to_read -= bodylen;
        } else {
            msg->cgihdr.body_to_read = 0;
        }

        padding = pend - pbodyend;
        if (padding < msg->cgihdr.padding_to_read) {
            msg->cgihdr.padding_to_read -= padding;
        } else {
            msg->cgihdr.padding_to_read = 0;
        }

        if (msg->cgihdr.type == FCGI_STDOUT) {
            if (bodylen == 0) {
                /* FCGI response body got end */
                iter = (pend - pbgn);
                continue;
            }

            if (msg->got_all_header == 0) {

                ppar[0]  = frameP(httpmsg->res_header_stream);
                arlen[0] = frameL(httpmsg->res_header_stream);
                ppar[1]  = pbody;
                arlen[1] = bodylen;

                pbyte = sun_find_mbytes((void **)ppar, arlen, 2,  "\r\n\r\n", 4, NULL, &ind);
                if (!pbyte) {
                    if (arlen[0] + arlen[1] > mgmt->srv_max_header_size) {
                        /* request header is too large, possibly a malicious attack */
                        return -104;
                    }
    
                    msg->got_all_header = 0;

                    frame_put_nlast(httpmsg->res_header_stream, pbody, bodylen);
                    iter = (pend - pbgn);

                    continue;
                }
    
                msg->got_all_header = 1;

                if (ind == 0) { /* \r\n\r\n exists in res_header_stream */

                    if (pbyte + 4 <= ppar[0] + arlen[0]) {
                        /* add all STDOUT body into httpmsg->res_body_chunk */
                        chunk_add_bufptr(httpmsg->res_body_chunk, pbody, bodylen, frm, NULL);

                    } else {
                        /* header trailer \r\n\r\n across the 2 buffer, move them 
                           into httpmsg->res_header_stream */
                        len = pbyte + 4 - ppar[0] - arlen[0];
                        frame_put_nlast(httpmsg->res_header_stream, pbody, len);

                        /* add STDOUT body into httpmsg->res_body_chunk */
                        chunk_add_bufptr(httpmsg->res_body_chunk, pbody + len, bodylen - len, frm, NULL);
                    }

                    /* move the pointer to the end of first FastCGI pdu */
                    iter = (pend - pbgn);

                } else if (ind == 1) {
                    len = pbyte + 4 - pbody;
                    frame_put_nlast(httpmsg->res_header_stream, pbody, len);

                    if (bodylen > len) {
                        /* add STDOUT body into httpmsg->res_body_chunk */
                        chunk_add_bufptr(httpmsg->res_body_chunk, pbody + len, bodylen - len, frm, NULL);
                    }

                    /* move the pointer to the end of first FastCGI pdu */
                    iter = (pend - pbgn);
                }
    
                ret = http_res_parse_header(httpmsg, 0);
                if (ret < 0) return -106;
    
                punit = http_header_get(httpmsg, 1, "Status", 6);
                if (punit && punit->valuelen > 0) {
                    status = strtol(HUValue(punit), (char **)&pbyte, 10);
                    if (pbyte) 
                        pbyte = skipOver(pbyte, HUValue(punit) + punit->valuelen - (char *)pbyte, " \t\r\n", 4);
                    str_secpy(sbuf, sizeof(sbuf)-1, pbyte, HUValue(punit) + punit->valuelen - (char *)pbyte);
                    httpmsg->SetStatus(httpmsg, status, sbuf);

                    http_header_del(httpmsg, 1, "Status", 6);

                } else {
                    httpmsg->SetStatus(httpmsg, 200, NULL);
                }

                http_header_append(httpmsg, 1, "Server", 6, mgmt->useragent, str_len(mgmt->useragent));
                if (http_header_get(httpmsg, 1, "Date", 4) == NULL)
                    http_header_append_date(httpmsg, 1, "Date", 4, time(NULL));
                if (http_header_get(httpmsg, 1, "Accept-Ranges", 13) == NULL)
                    http_header_append(httpmsg, 1, "Accept-Ranges", 13, "bytes", 5);
                if (http_header_get(httpmsg, 1, "Transfer-Encoding", 17) == NULL)
                    http_header_append(httpmsg, 1, "Transfer-Encoding", 17, "chunked", 7);
 
                httpmsg->res_body_flag = BC_TE;

                ret = http_res_encoding(httpmsg);
                if (ret < 0) return -107;
 
                httpmsg->res_encoded = 1;
                httpmsg->state = HTTP_MSG_REQUEST_HANDLED;

                continue;

            } else {  //STDOUT header has been got before
                /* add all STDOUT body into httpmsg->res_body_chunk */
                chunk_add_bufptr(httpmsg->res_body_chunk, pbody, bodylen, frm, NULL);

                /* move the pointer to the end of first FastCGI pdu */
                iter = (pend - pbgn);
                continue;
            }

        } else if (msg->cgihdr.type == FCGI_END_REQUEST) {
            if (bodylen != 8) {
            }

            msg->app_status = (pbody[0] << 24) + (pbody[1] << 16) + (pbody[2] << 8) + pbody[3];
            msg->proto_status = pbody[4];

            /* move the pointer to the end of first FastCGI pdu */
            iter = (pend - pbgn);

            msg->got_end_request = 1;

            /* FcgiMsg has done all job, now unbind it from FcgiCon */
            pcon->msg = NULL;
            http_fcgicon_msg_del(pcon, msg);

            /* close FcgiMsg */
            http_fcgimsg_close(msg);

            /* If multiple HTTP requests on a long TCP connection are FastCGI requests,
               is it appropriate to use long-life connection or short-life connection for
               TCP or unix-socket connection between eJet and FastCGI server? Theoretically,
               the connection between eJet and php-fpm should be long-lived, which can reduce
               the overhead required for frequent connection establishment. However, after
               testing, it is found that php-fpm has defects in sending and receiving FastCGI
               requests/responses with long connections (it may need to be optimized in the new
               version). Therefore, when FastCGI's response is successfully delivered to the
               HTTP client, the connection between eJet and FastCGI server will be forcibly closed. */

            http_fcgicon_close(srv, conid);

            /* unset httpmsg's fcgimsg value */
            httpmsg->fcgimsg = NULL;

            /* set the current size as the end-size of chunk object */
            chunk_set_end(httpmsg->res_body_chunk);

            /* extracted data from FcgiCon/FcgiMsg to HTTP response successfully!
               now send the HTTP response to client */ 

        } else if (msg->cgihdr.type == FCGI_STDERR) {
            /* remove the octets of unknown FastCGI pdu */
            iter = (pend - pbgn);

        } else {
            /* remove the octets of unknown FastCGI pdu */
            iter = (pend - pbgn);
        }
    } //end while

    if (iter + 8 >= num) {
        frame_put_nlast(pcon->rcvstream, pbgn + iter, num - iter);
    }

    http_cli_send(mgmt, httpmsg->conid);
    return 0;
}


int http_fcgi_handle (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    int        ret = 0;

    if (!msg) return -1;

    ret = http_fcgi_examine(msg);
    if (ret < 0) return ret;

    return http_fcgi_launch(msg);
}

int http_fcgi_check (void * vmsg, void * purl, int urlen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    char     * url = (char *)purl;
    int        ret = 0;
 
    if (!msg) return 0;

    if (!msg->ploc) return 0;
 
    /* /w/h/wc.php?key=setbitfunc&stamp=327239843983
     * location = {
           type = fastcgi;
           path = [ "\.(php|php?)$", '~*'];

           passurl = fastcgi://121.17.94.8:9000;

           index = [ index.php ];
           root = /data/wwwroot/wordproc;
            }
     * url --> fastcgi://121.17.94.8:9000/
     */
 
    ret = http_loc_passurl_get(msg, SERV_FASTCGI, url, urlen);
    if (ret > 0) {
        if (msg->fwdurl) k_mem_free(msg->fwdurl, msg->alloctype, msg->kmemblk);
        msg->fwdurllen = strlen(url);
        msg->fwdurl = k_mem_str_dup(url, msg->fwdurllen, msg->alloctype, msg->kmemblk);

        return 1;
    }
 
    return 0;
}

int http_fcgi_examine (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    char       url[512];

    if (!msg) return -1;

    /* check the request if it's to be transformed to FCGI server */
    if (http_fcgi_check(msg, url, sizeof(url)-1) <= 0)
        return -100;

    msg->fastcgi = 1; 

    return 0;
}

 
void * http_fcgi_send_start (void * vfcgisrv, void * vhttpmsg)
{
    FcgiSrv    * cgisrv = (FcgiSrv *)vfcgisrv;
    HTTPMsg    * httpmsg = (HTTPMsg *)vhttpmsg;
    FcgiMsg    * cgimsg = NULL;
    FcgiCon    * cgicon = NULL;

    if (!cgisrv) return NULL;
    if (!httpmsg) return NULL;

    /* create one FastCGI FcgiMsg object */
    cgimsg = httpmsg->fcgimsg = http_fcgimsg_open(cgisrv, httpmsg);

    cgicon = http_fcgisrv_connect(cgisrv, httpmsg->workerid);
    if (cgicon) { 
        http_fcgicon_msg_add(cgicon, cgimsg);
     
        http_fcgi_srv_send(cgicon, cgimsg);
     
    } else {
        http_fcgisrv_msg_push(cgisrv, cgimsg);
    }

    httpmsg->fcgi_resend++;

    return cgicon;
}

int http_fcgi_launch (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    FcgiSrv  * cgisrv = NULL;
    FcgiMsg  * cgimsg = NULL;

    if (!msg) return -1;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;

    if (msg->fastcgi != 1) return -60;

    if (!msg->fwdurl || msg->fwdurllen <= 0) return -70;

#if defined _DEBUG
  print_request(msg, stdout);
#endif

    /* It is necessary to solve the problem of repeatedly calling this function. */

    cgisrv = http_fcgisrv_open(mgmt, msg->fwdurl, 100);
    if (!cgisrv || (cgisrv->trytimes > 16 && cgisrv->failtimes * 100 / cgisrv->trytimes >= 97)) {
        /* if the success ratio of connecting to CGIServer is lower than 3%, reply error to client */
        if (!msg->res_encoded) {
            msg->SetStatus(msg, 503, NULL);
            msg->AsynReply(msg, 1, 1);
        }
        return -300;
    }

    if ((cgimsg = msg->fcgimsg) && cgimsg->pcon && http_fcgicon_msg_exist(cgimsg->pcon, cgimsg) >= 0) {
        /* if FastCGI msg is created and the fcgimsg is bound to one fcgicon,
           no subsequent operation is required */
        return 0;
    }

    http_fcgi_send_start(cgisrv, msg);

    return 0;
}

int http_fcgi_srv_send (void * vfcgicon, void * vfcgimsg)
{
    FcgiCon     * cgicon = (FcgiCon *)vfcgicon;
    FcgiMsg     * cgimsg = (FcgiMsg *)vfcgimsg;
    HTTPCon     * clicon = NULL;
    HTTPMsg     * climsg = NULL;
    HTTPChunk   * chunk  = NULL;
    frame_t     * frm = NULL;
 
    uint8         isend = 0;
    int           ret;
    int           rcvslen = 0;
    uint8       * pbgn = NULL;
    int           num = 0;
 
    if (!cgimsg) return -2;
 
    climsg = cgimsg->httpmsg;
    if (!climsg) return -3;
 
    clicon = climsg->pcon;
    if (!clicon) return -4;
 
    if (climsg->fastcgi != 1) return -10;
    if (cgimsg->httpmsg != climsg) return -11;
 
    frm = clicon->rcvstream;

    pbgn = frameP(frm);
    num = frameL(frm);

    if (climsg->req_gotall_body || num <= 0) {
        if (cgicon)
            return http_fcgi_send(cgicon->srv, cgicon->conid);
        return 0;
    }

    EnterCriticalSection(&clicon->excCS);
    if ((num = frameL(clicon->rcvstream)) > 0) {
        arr_push(cgimsg->req_rcvs_list, frm);
        clicon->rcvstream = frame_alloc(0, clicon->alloctype, clicon->kmemblk);
    }
    LeaveCriticalSection(&clicon->excCS);

    if (climsg->req_body_flag == BC_CONTENT_LENGTH &&
        climsg->req_body_length - cgimsg->req_body_iolen > 0 && num > 0)
    {
        /* remaining body to be sent */
        rcvslen = climsg->req_body_length - cgimsg->req_body_iolen;
        rcvslen = min(num, rcvslen);
 
        climsg->req_body_iolen += rcvslen;
        cgimsg->req_body_iolen += rcvslen;
        climsg->req_stream_recv += rcvslen;

        isend = cgimsg->req_body_iolen >= climsg->req_body_length;

        if (rcvslen > 0) {
            http_fcgimsg_stdin_encode_chunk(cgimsg, pbgn, rcvslen, frm, isend);
        }

    } else if (climsg->req_body_flag == BC_TE && num > 0) {
 
        chunk = (HTTPChunk *)climsg->req_chunk;
        if (chunk == NULL) {
            chunk = climsg->req_chunk = http_chunk_alloc(climsg->alloctype, climsg->kmemblk);
        }

        ret = http_chunk_add_bufptr(chunk, pbgn, num, &rcvslen);
 
        isend = chunk->gotall;

        if (ret >= 0 && rcvslen > 0) {
            http_fcgimsg_stdin_encode_chunk(cgimsg, pbgn, rcvslen, frm, isend);
        }
 
        cgimsg->req_body_iolen += rcvslen;
        cgimsg->req_body_length += rcvslen;

        climsg->req_body_iolen += rcvslen;
        climsg->req_body_length += rcvslen;
        climsg->req_stream_recv += rcvslen;
 
    } else if (climsg->req_body_flag == BC_NONE || climsg->req_body_length == 0) {
        isend = 1;
        http_fcgimsg_stdin_end_encode_chunk(cgimsg);
    }

    if (isend && num > rcvslen) {
        frame_put_nlast(clicon->rcvstream, pbgn + rcvslen, num - rcvslen);
    }
 
    if (isend) {
        clicon->rcv_state = HTTP_CON_READY;
        climsg->req_gotall_body = 1;
        clicon->rcv_state = HTTP_CON_READY;
    } else {
        clicon->rcv_state = HTTP_CON_WAITING_BODY;
    }

    if (cgicon)
        return http_fcgi_send(cgicon->srv, cgicon->conid);
    return 0;
}

int http_fcgi_con_lifecheck (void * vsrv, ulong conid)
{
    FcgiSrv  * srv = (FcgiSrv *)vsrv;
    FcgiCon  * pcon = NULL;
    HTTPMgmt * mgmt = NULL;
    time_t     curt = 0;
    int        num = 0;
 
    if (!srv) return -1;
 
    pcon = http_fcgisrv_con_get(srv, conid);
    if (!pcon) return -2;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return -3;
 
    num = arr_num(pcon->msg_list) + http_fcgisrv_msg_num(pcon->srv);
    time(&curt);
 
    if (num <= 0 && curt - pcon->stamp >= mgmt->fcgi_keepalive_time) {
        /* keep the connection alive waiting for the new fcgimsg. */
        return http_fcgicon_close(srv, conid);
    }
 
    if (pcon->snd_state < FCGI_CON_SEND_READY && curt - pcon->stamp >= mgmt->fcgi_connecting_time) {
        /* if exceeds the max time that builds TCP connection to remote server, close it.
           seems that it never go here */
        return http_fcgicon_close(srv, conid);
    }
 
    if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->fcgi_conn_idle_time) {
        /* when in sending or receiving state, the TCP connection is waiting and 
           no I/O operations occures.
           e.g. long-polling connection to server can exist for conn_idle_time */
        return http_fcgicon_close(srv, conid);
    }
 
    if (num > 0 && pcon->snd_state == FCGI_CON_SEND_READY && pcon->rcv_state == FCGI_CON_READY) {
        /* FcgiCon sending and receivng facilities are in ready state */
        http_fcgi_send_probe(srv, conid);
    }
 
    pcon->life_timer = iotimer_start(pcon->pcore,
                                  6 * 1000,
                                  t_fcgi_srv_con_life,
                                  (void *)conid,
                                  http_fcgisrv_pump,
                                  srv, iodev_epumpid(pcon->pdev));
 
    return 0;
}

