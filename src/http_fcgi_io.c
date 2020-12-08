/*
 * Copyright (c) 2003-2020 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"
#include "http_con.h"
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_chunk.h"
#include "http_header.h"
#include "http_response.h"
#include "http_cli_io.h"

#include "http_fcgi_srv.h"
#include "http_fcgi_msg.h"
#include "http_fcgi_con.h"
#include "http_fcgi_io.h"

extern HTTPMgmt * gp_httpmgmt;


int http_fcgi_send_probe (void * vcon)
{
    FcgiCon  * pcon = (FcgiCon *)vcon;
    FcgiMsg  * msg = NULL;
    int        num = 0;
 
    if (!pcon) return -1;
 
    if (pcon->snd_state < FCGI_CON_SEND_READY) return -100;
 
    num = arr_num(pcon->msg_list) + http_fcgisrv_msg_num(pcon->srv);
    if (num <= 0) {
        if (pcon->snd_state == FCGI_CON_FEEDING)
            pcon->snd_state = FCGI_CON_SEND_READY;

        return 0;
    }
 
    msg = http_fcgicon_msg_first(pcon);
    if (msg && (msg->reqsent > 0 ||
                 ( msg->req_body_flag == BC_CONTENT_LENGTH &&
                   msg->req_header_sent >= msg->req_header_length &&
                   msg->req_body_sent >= msg->req_body_length ) ||
                 ( msg->req_body_flag == BC_NONE && msg->req_header_sent >= msg->req_header_length ) ||
                 ( msg->req_body_flag == BC_TE && http_chunk_gotall(msg->req_chunk) )
               )
       )
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

int http_fcgi_send (void * vcon)
{
    FcgiCon  * pcon = (FcgiCon *)vcon;
    FcgiMsg  * msg = NULL;
    time_t     curt = 0;

    if (!pcon) return -1;

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
                 ( msg->req_body_flag == BC_CONTENT_LENGTH &&
                   msg->req_header_sent >= msg->req_header_length && 
                   msg->req_body_sent >= msg->req_body_length ) || 
                 ( msg->req_body_flag == BC_NONE && msg->req_header_sent >= msg->req_header_length ) ||
                 ( msg->req_body_flag == BC_TE && http_chunk_gotall(msg->req_chunk) )
               )
            {
                pcon->snd_state = FCGI_CON_SEND_READY;
                return 0;
            }

            return http_fcgi_srv_send(pcon, msg);
 
        } else {
            curt = time(0);
            while ((msg = http_fcgisrv_msg_pull(pcon->srv)) != NULL) {
                if (curt - msg->createtime > 60) {
                    http_fcgimsg_close(msg);
                    msg = NULL;
                    continue;
                }
 
                pcon->msg = msg;
                msg->reqsent = 0;
                msg->req_stream_sent = 0;
 
                http_fcgicon_msg_add(pcon, msg);
 
                return http_fcgi_srv_send(pcon, msg);
            }
        }
    }

    pcon->snd_state = FCGI_CON_SEND_READY;

    return 0;
}

int http_fcgicon_crash_handle (void * vcon)
{
    FcgiCon    * pcon = (FcgiCon *)vcon;
    FcgiMsg    * msg = NULL;
    HTTPMsg    * httpmsg = NULL;

    if (!pcon) return -1;

    msg = http_fcgicon_msg_first(pcon);
 
    if (msg && (httpmsg = msg->httpmsg)) {
        if (!msg->got_all_header && httpmsg->fcgi_resend < 3) {
            frame_empty(httpmsg->res_header_stream);
            http_fcgi_send_start(pcon->srv, httpmsg);
 
            http_fcgicon_close(pcon);
            return 0;
        }
    }
 
    http_fcgimsg_pre_crash(msg, 503);
    http_fcgicon_close(pcon);
 
    return -100;
}

int http_fcgi_recv (void * vcon)
{
    FcgiCon    * pcon = (FcgiCon *)vcon;
    FcgiMsg    * msg = NULL;
    HTTPMsg    * httpmsg = NULL;
    HTTPCon    * httpcon = NULL;
    HTTPMgmt   * mgmt = NULL;
    int          ret = 0, num = 0;
    int          err = 0;
    uint8        crashed = 0;
 
    if (!pcon) return -1;
 
    msg = http_fcgicon_msg_first(pcon);
    if (msg) httpmsg = msg->httpmsg;
    if (httpmsg) mgmt = httpmsg->httpmgmt;
    if (!mgmt) mgmt = gp_httpmgmt;
 
    if (msg && httpmsg && mgmt &&
        chunk_rest_size(httpmsg->res_body_chunk, 0) >= mgmt->fcgi_buffer_size)
    {
        /* congestion control: by neglecting the read-ready event,
           underlying TCP/UnixSocket stack recv-buffer will be full soon.
           TCP/UnixSocket stack will start congestion control mechanism */
        iodev_del_notify(pcon->pdev, RWF_READ);
        pcon->read_ignored++;
 
        httpcon = httpmsg->pcon;
 
        if (httpcon && !tcp_connected(iodev_fd(httpcon->pdev))) {
           http_con_close(httpmsg->pcon);
           http_fcgicon_close(pcon);
           return -100;
        }
 
        time(&pcon->stamp);
        if (pcon->srv)
            time(&((FcgiSrv *)(pcon->srv))->stamp);
 
        return 0;
    }

    while (1) {
 
        crashed = 0;
 
        ret = frame_tcp_nbzc_recv(pcon->rcvstream, iodev_fd(pcon->pdev), &num, &err);
        if (ret < 0) {
            crashed = 1;
 
            if (frameL(pcon->rcvstream) <= 0) {
                return http_fcgicon_crash_handle(pcon);
            }
        }
 
        time(&pcon->stamp);
        if (pcon->read_ignored > 0)
            pcon->read_ignored = 0;
 
        if (pcon->srv)
            time(&((FcgiSrv *)(pcon->srv))->stamp);
 
        if (frameL(pcon->rcvstream) <= 0) 
           return 0;

        ret = http_fcgi_recv_forward(pcon);
        if (ret < 0) {
            return http_fcgicon_crash_handle(pcon);
 
        } else if (ret == 0) {
            if (crashed) {
                http_fcgicon_crash_handle(pcon);
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
                    http_fcgi_send(pcon);
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
                chunk_add_bufptr(httpmsg->res_body_chunk, frameP(httpmsg->res_body_stream), bodylen, NULL);
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

int http_fcgi_recv_forward (void * vcon)
{
    FcgiCon  * pcon = (FcgiCon *)vcon;
    FcgiMsg  * msg = NULL;
    FcgiSrv  * srv = NULL;
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

    frm = pcon->rcvstream;
    arr_push(httpmsg->res_rcvs_list, frm);
    pcon->rcvstream = frame_new(8192);
 
    pbgn = frameP(frm);
    num = frameL(frm);
    iter = 0;

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
                        chunk_add_bufptr(httpmsg->res_body_chunk, pbody, bodylen, frm);

                    } else {
                        /* header trailer \r\n\r\n across the 2 buffer, move them 
                           into httpmsg->res_header_stream */
                        len = pbyte + 4 - ppar[0] - arlen[0];
                        frame_put_nlast(httpmsg->res_header_stream, pbody, len);

                        /* add STDOUT body into httpmsg->res_body_chunk */
                        chunk_add_bufptr(httpmsg->res_body_chunk, pbody + len, bodylen - len, frm);
                    }

                    /* move the pointer to the end of first FastCGI pdu */
                    iter = (pend - pbgn);

                } else if (ind == 1) {
                    len = pbyte + 4 - pbody;
                    frame_put_nlast(httpmsg->res_header_stream, pbody, len);

                    if (bodylen > len) {
                        /* add STDOUT body into httpmsg->res_body_chunk */
                        chunk_add_bufptr(httpmsg->res_body_chunk, pbody + len, bodylen - len, frm);
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
 
                httpmsg->issued = 1;
                httpmsg->state = HTTP_MSG_REQUEST_HANDLED;

                continue;

            } else {  //STDOUT header has been got before
                /* add all STDOUT body into httpmsg->res_body_chunk */
                chunk_add_bufptr(httpmsg->res_body_chunk, pbody, bodylen, frm);

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

    http_cli_send(httpmsg->pcon);
    return 0;
}


int http_fcgi_check (void * vmsg, void * purl, int urlen)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    char     * url = (char *)purl;
    int        ret = 0;
 
    if (!msg) return 0;

    if (!msg->ploc) return 0;
 
    /* location / {
     *     path = [ '/', '^~' ]; 
     *     type  =  server;
     *     index =  [ index.html, index.htm ];
     *     root  =  /opt/httpdoc/;
     * }
     * location { 
     *     path = [ '/cache/', '^~' ];
     *     type = proxy
     *     passurl = http://www.abcxxx.com/;
     * }
     * /cache/cdn/view?fid=3782837A0FA83B764E36A377B366CE98&stamp=327239843983
     * url -->
     * http://www.abcxxx.com/cdn/view?fid3782837A0FA83B764E36A377B366CE98&stamp=327239843983
     */
 
    ret = http_loc_passurl_get(msg, SERV_FASTCGI, url, urlen);
    if (ret > 0) {
        if (msg->fwdurl) kfree(msg->fwdurl);
        msg->fwdurllen = strlen(url);
        msg->fwdurl = str_dup(url, msg->fwdurllen);

        return 1;
    }
 
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
         
    cgicon = http_fcgisrv_connect(cgisrv);
    if (cgicon) { 
        /* upcoming R/W events of proxycon will delivered to current thread.
           for the Read/Write pipeline of 2 HTTP connections */
        iodev_workerid_set(cgicon->pdev, 1);
     
        http_fcgicon_msg_add(cgicon, cgimsg);
     
        http_fcgi_srv_send(cgicon, cgimsg);
     
    } else {
        http_fcgisrv_msg_push(cgisrv, cgimsg);
    }

    httpmsg->fcgi_resend++;

    return cgicon;
}

int http_fcgi_srv_send (void * vfcgicon, void * vfcgimsg)
{
    FcgiCon     * cgicon = (FcgiCon *)vfcgicon;
    FcgiMsg     * cgimsg = (FcgiMsg *)vfcgimsg;
    HTTPCon     * clicon = NULL;
    HTTPMsg     * climsg = NULL;
    HTTPChunk   * chunk  = NULL;

    uint8         justsaveit = 0;
    int           i, ret;
    int           tosend = 0;
    int           sentbody = 0;
    int           sentnum = 0;

    int           hdrlen = 0;
    int           bodylen = 0;
    int           rcvslen = 0;

    uint8       * pbgn = NULL;
    int           num = 0;

    struct iovec  iov[100];  //at most 32*3 + 2
    int           iovcnt = 0;

    if (!cgicon) return -1;
    if (!cgimsg) return -2;

    if (cgicon->snd_state < FCGI_CON_SEND_READY)
        return -100;

    climsg = cgimsg->httpmsg;
    if (!climsg) return -3;

    clicon = climsg->pcon;
    if (!clicon) return -4;

    if (climsg->fastcgi != 1) return -10;
    if (cgimsg->httpmsg != climsg) return -11;

    cgicon->snd_state = FCGI_CON_FEEDING;

    chunk = (HTTPChunk *)climsg->req_chunk;
 
    if (cgimsg != http_fcgicon_msg_first(cgicon)) {
        justsaveit = 1;
    }
 
    if (cgimsg->req_header_sent < cgimsg->req_header_length) {
        iov[iovcnt].iov_base = frameP(cgimsg->fcgi_request) + cgimsg->req_header_sent;
        hdrlen = iov[iovcnt].iov_len = cgimsg->req_header_length - cgimsg->req_header_sent;
        tosend += hdrlen;
        iovcnt++;
    }
 
    /* body-length sent before */
    sentbody = cgimsg->req_body_sent;
 
    http_fcgimsg_stdin_init(cgimsg);

    /* clicon received data from client and transformed into FastCGI request. 
     * then deliver the FastCGI request to CGI Server. For some reason of network
     * fluctuation, not all data can be realtime-sent to destination successfully.
     * Therefore, unsent data are removed from clicon->rcvstream to climsg->req_body_stream.
     * When write-ready of cgicon, these data will be sent firstly */
    pbgn = frameP(climsg->req_body_stream);
    num = frameL(climsg->req_body_stream);

    if (climsg->req_body_flag == BC_CONTENT_LENGTH &&
        climsg->req_body_length - sentbody > 0 && num > 0)
    {
        /* remaining body to be sent */
        bodylen = climsg->req_body_length - sentbody;
        bodylen = min(num, bodylen);

        sentbody += bodylen;
        tosend += bodylen;
 
        if (bodylen > 0)
            http_fcgimsg_stdin_encode(cgimsg, pbgn, bodylen, sentbody >= climsg->req_body_length);

    } else if (climsg->req_body_flag == BC_TE && num > 0) {
        bodylen = num;

        sentbody += bodylen;
        tosend += bodylen;
 
        if (bodylen > 0)
            http_fcgimsg_stdin_encode(cgimsg, pbgn, bodylen, chunk->gotall);
    }

    pbgn = frameP(clicon->rcvstream);
    num = frameL(clicon->rcvstream);
 
    if (climsg->req_body_flag == BC_CONTENT_LENGTH &&
        climsg->req_body_length - sentbody > 0 && num > 0)
    {
        /* remaining body to be sent */
        rcvslen = climsg->req_body_length - sentbody;
        rcvslen = min(num, rcvslen);

        sentbody += rcvslen;
        tosend += rcvslen;
        climsg->req_stream_recv += rcvslen;
 
        if (rcvslen > 0)
            http_fcgimsg_stdin_encode(cgimsg, pbgn, rcvslen, sentbody >= climsg->req_body_length);

    } else if (climsg->req_body_flag == BC_TE && num > 0) {

        ret = http_chunk_add_bufptr(chunk, pbgn, num, &rcvslen);
        if (ret >= 0 && rcvslen > 0) {
            http_fcgimsg_stdin_encode(cgimsg, pbgn, rcvslen, chunk->gotall);
        }

        sentbody += rcvslen;
        tosend += rcvslen;
        climsg->req_stream_recv += rcvslen;

    } else if (climsg->req_body_flag == BC_NONE || climsg->req_body_length == 0) {
        http_fcgimsg_stdin_encode_end(cgimsg);
    }

    for (i = 0; i < cgimsg->fcgi_stdin_num && i < 32; i++) {
        iov[iovcnt].iov_base = cgimsg->fcgi_stdin_header[i];
        iov[iovcnt].iov_len = 8;
        iovcnt++;

        if (cgimsg->fcgi_stdin_body_len[i] > 0 && cgimsg->fcgi_stdin_body[i] != NULL) {
            iov[iovcnt].iov_base = cgimsg->fcgi_stdin_body[i];
            iov[iovcnt].iov_len = cgimsg->fcgi_stdin_body_len[i];
            iovcnt++;
        }

        if (cgimsg->fcgi_stdin_padding_len[i] > 0) {
            iov[iovcnt].iov_base = cgimsg->fcgi_stdin_padding[i];
            iov[iovcnt].iov_len = cgimsg->fcgi_stdin_padding_len[i];
            iovcnt++;
        }
    }

    if (!justsaveit && iovcnt > 0) {
        ret = tcp_writev(iodev_fd(cgicon->pdev), iov, iovcnt, &sentnum, NULL);
        if (ret < 0) {
            climsg->fastcgi = 0;
            climsg->SetStatus(climsg, 503, NULL);
            climsg->Reply(climsg);

            http_fcgicon_close(cgicon);
 
            return -200;
        }
 
        cgimsg->req_stream_sent += sentnum;

        if (sentnum < hdrlen) {
            cgimsg->req_header_sent += sentnum;
            sentbody = 0;
        } else {
            cgimsg->req_header_sent += hdrlen;
            sentbody = sentnum - hdrlen;
        }
 
        sentbody = http_fcgimsg_stdin_body_sentnum(cgimsg, sentbody);
        cgimsg->req_body_sent += sentbody;

        time(&cgicon->stamp);

    } else {
        sentbody = 0;
    }

    if (climsg->req_body_flag == BC_CONTENT_LENGTH) {

        if (sentbody > 0) {
            if (sentbody >= bodylen) {
                /* all data in climsg->req_body_stream buffered in last time has been sent
                   out. clear the buffer */
                frame_empty(climsg->req_body_stream);
 
                sentbody -= bodylen;
                if (sentbody >= rcvslen) {
                    /* all data in clicon->rcvstream have been sent */
                    frame_del_first(clicon->rcvstream, rcvslen);
 
                    /* all bytes remaining in 2 buffers are sent out,
                       check if full response is sent successfully */
                    if (cgimsg->req_body_sent >= climsg->req_body_length)
                        goto succ;
 
                } else {
                    frame_del_first(clicon->rcvstream, sentbody);
 
                    /* only part of clicon rcvstream are sent, remaining bytes should
                       be moved to climsg->req_body_stream for next sending */

                    frame_put_nlast(climsg->req_body_stream, frameP(clicon->rcvstream), rcvslen - sentbody);
                    frame_del_first(clicon->rcvstream, rcvslen - sentbody);
                }

            } else {
                /* only part data in climsg->req_body_stream sent out, all data in clicon
                   rcvstream are not sent out */

                frame_del_first(climsg->req_body_stream, sentbody);
 
                /* move unsent data in clicon->rcvstream into climsg->req_body_stream
                   for next sending */

                frame_put_nlast(climsg->req_body_stream, pbgn, rcvslen);
                frame_del_first(clicon->rcvstream, rcvslen);

            }

        } else { //all data in clicon rcvstream are not sent
            /* move unsent data in clicon->rcvstream to climsg->req_body_stream
               for next sending */
            frame_put_nlast(climsg->req_body_stream, pbgn, rcvslen);
            frame_del_first(clicon->rcvstream, rcvslen);
        }

        if (cgimsg->req_body_sent + frameL(climsg->req_body_stream) < climsg->req_body_length) {
            clicon->rcv_state = HTTP_CON_WAITING_BODY;
        } else {
            clicon->rcv_state = HTTP_CON_READY;
        }
 
        if (cgimsg->req_body_sent >= climsg->req_body_length)
            goto succ;

    } else if (climsg->req_body_flag == BC_TE) {
        if (sentbody > 0) {
            if (sentbody >= bodylen) {
                /* all data in climsg->req_stream_body have been sent succ */
                frame_empty(climsg->req_body_stream);
 
                sentbody -= bodylen;
                if (sentbody >= rcvslen) {
                    /* all data in clicon->rcvstream have been sent */
                    frame_del_first(clicon->rcvstream, rcvslen);
 
                    /* all data remaining in 2 buffers are sent out,
                       check if full request is sent successfully */
                    if (chunk->gotall)
                        goto succ;
 
                } else {
                    /* only partial bytes in TE entity are sent */
                    frame_del_first(clicon->rcvstream, sentbody);
 
                    /* part of rcvstream sent, remaining bytes should be put into req_body_stream
                       for next sending */
                    frame_put_nlast(climsg->req_body_stream, frameP(clicon->rcvstream), rcvslen - sentbody);
                    frame_del_first(clicon->rcvstream, rcvslen - sentbody);
                }
 
            } else {
                /* only partial bytes in climsg->req_stream_body sent out */
                frame_del_first(climsg->req_body_stream, sentbody);
 
                /* move unsent data in clicon->rcvstream into climsg->req_body_stream
                   for next sending */
                frame_put_nlast(climsg->req_body_stream, pbgn, rcvslen);
                frame_del_first(clicon->rcvstream, rcvslen);
            }

        } else { //all data in clicon rcvstream are not sent
            /* move unsent data in clicon->rcvstream to climsg->req_body_stream
               for next sending */

            frame_put_nlast(climsg->req_body_stream, pbgn, rcvslen);
            frame_del_first(clicon->rcvstream, rcvslen);
        }
 
        if (chunk->gotall) {
            clicon->rcv_state = HTTP_CON_READY;
 
            if (cgimsg->req_header_sent >= climsg->req_header_length &&
                frameL(climsg->req_body_stream) == 0)
                goto succ;
 
        } else {
            clicon->rcv_state = HTTP_CON_WAITING_BODY;
        }

    } else {
        clicon->rcv_state = HTTP_CON_READY;
 
        if (cgimsg->req_header_sent >= cgimsg->req_header_length)
            goto succ;
    }
    
    if (cgimsg->req_header_sent < cgimsg->req_header_length ||
        frameL(climsg->req_body_stream) > 0)
    {
        iodev_add_notify(cgicon->pdev, RWF_WRITE);
    }
 
    cgicon->snd_state = FCGI_CON_SEND_READY;
    return 0;

succ:
    clicon->rcv_state = HTTP_CON_READY;
    cgimsg->reqsent = 1;
 
    cgicon->snd_state = FCGI_CON_SEND_READY;

    /* FCGI-Request Message has been sent successfully */
    return 1;
}


int http_fcgi_con_lifecheck (void * vcon)
{
    FcgiCon  * pcon = (FcgiCon *)vcon;
    FcgiSrv  * srv = NULL;
    HTTPMgmt * mgmt = NULL;
    time_t     curt = 0;
    int        num = 0;
 
    if (!pcon) return -1;
 
    srv = (FcgiSrv *)pcon->srv;
    if (!srv) return -2;

    mgmt = (HTTPMgmt *)srv->mgmt;
    if (!mgmt) return -3;
 
    num = arr_num(pcon->msg_list) + http_fcgisrv_msg_num(pcon->srv);
    time(&curt);
 
    if (num <= 0 && curt - pcon->stamp >= mgmt->fcgi_keepalive_time) {
        /* keep the connection alive waiting for the new fcgimsg. */
        return http_fcgicon_close(pcon);
    }
 
    if (pcon->snd_state < FCGI_CON_SEND_READY && curt - pcon->stamp >= mgmt->fcgi_connecting_time) {
        /* if exceeds the max time that builds TCP connection to remote server, close it.
           seems that it never go here */
        return http_fcgicon_close(pcon);
    }
 
    if (curt > pcon->stamp && curt - pcon->stamp >= mgmt->fcgi_conn_idle_time) {
        /* when in sending or receiving state, the TCP connection is waiting and 
           no I/O operations occures.
           e.g. long-polling connection to server can exist for conn_idle_time */
        return http_fcgicon_close(pcon);
    }
 
    if (num > 0 && pcon->snd_state == FCGI_CON_SEND_READY && pcon->rcv_state == FCGI_CON_READY) {
        /* FcgiCon sending and receivng facilities are in ready state */
        http_fcgi_send_probe(pcon);
    }
 
    pcon->life_timer = iotimer_start(pcon->pcore,
                                  6 * 1000,
                                  t_fcgi_srv_con_life,
                                  (void *)pcon->conid,
                                  http_fcgisrv_pump,
                                  pcon->srv);
 
    return 0;
}

