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

#include "http_mgmt.h"
#include "http_header.h"
#include "http_msg.h"
#include "http_con.h"
#include "http_srv.h"
#include "http_request.h"
#include "http_response.h"
#include "http_chunk.h"
#include "http_variable.h"
#include "http_cache.h"
#include "http_log.h"

#include "http_form.h"
#include "http_dispdir.h"
#include "http_cgi.h"
#include "http_pagetpl.h"

extern HTTPMgmt * gp_httpmgmt;

int http_msg_cmp_http_msg(void * a, void * b)
{
    HTTPMsg * msga = (HTTPMsg *)a;
    HTTPMsg * msgb = (HTTPMsg *)b;

    if (!msga || !msgb) return -1;

    if (msga->msgid == msgb->msgid) return 0;
    if (msga->msgid > msgb->msgid) return 1;
    return -1;
}


int http_msg_cmp_msgid (void * a, void * pat)
{
    HTTPMsg * msg = (HTTPMsg *)a;
    ulong     msgid = (ulong)pat;

    if (!msg) return -1;

    if (msg->msgid == msgid) return 0;
    if (msg->msgid > msgid) return 1;
    return -1;
}


ulong http_msg_hash_msgid (void * key)
{
    ulong msgid = (ulong)key;
    return msgid;
}


int http_mgmt_msg_free (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;

    if (!msg) return -1;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -2;

    if (http_msg_free(msg) == 0)
        mpool_recycle(mgmt->msg_pool, msg);

    return 1;
}

int http_msg_free (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMsg  * proxymsg = NULL;

    if (!msg) return -1;

    if (msg->proxied > 0 && (proxymsg = msg->proxymsg)) {
        if (proxymsg->proxied > 0 && proxymsg->proxymsg == msg) {
            proxymsg->proxymsg = NULL;
        }
        msg->proxymsg = NULL;
    }

    if (msg->script_var_tab) {
        ht_free_all(msg->script_var_tab, var_obj_free);
        msg->script_var_tab = NULL;
    }

    /* clear the buffer/data management resources which handle the http request */
    if (msg->uri) {
        http_uri_free(msg->uri);
        msg->uri = NULL;
    }
    if (msg->absuri) {
        http_uri_free(msg->absuri);
        msg->absuri = NULL;
    }
    if (msg->docuri) {
        http_uri_free(msg->docuri);
        msg->docuri = NULL;
    }

    if (msg->req_file_handle) {
        native_file_close(msg->req_file_handle);
        msg->req_file_handle = NULL;
    }
    if (msg->req_file_name) {
        unlink(msg->req_file_name);
        msg->req_file_cache = 0;

        k_mem_free(msg->req_file_name, msg->alloctype, msg->kmemblk);
        msg->req_file_name = NULL;
    }

    http_req_delallcookie(msg);
    http_header_delall(msg, 0);

    if (msg->req_cookie_table) {
        ht_free(msg->req_cookie_table);
        msg->req_cookie_table = NULL;
    }

    if (msg->req_header_table) {
        ht_free(msg->req_header_table);
        msg->req_header_table = NULL;
    }

    if (msg->req_header_list) {
        arr_free(msg->req_header_list);
        msg->req_header_list = NULL;
    }

    if (msg->req_header_stream) {
        frame_delete(&msg->req_header_stream);
        msg->req_header_stream = NULL;
    }
    if (msg->req_body_stream) {
        frame_delete(&msg->req_body_stream);
        msg->req_body_stream = NULL;
    }
    if (msg->req_stream) {
        frame_delete(&msg->req_stream);
        msg->req_stream = NULL;
    }

    if (msg->req_chunk) {
        http_chunk_free(msg->req_chunk);
        msg->req_chunk = NULL;
    }

    if (msg->req_body_chunk) {
        chunk_free(msg->req_body_chunk);
        msg->req_body_chunk = NULL;
    }

    if (msg->req_rcvs_list) {
        arr_pop_free(msg->req_rcvs_list, frame_free);
        msg->req_rcvs_list = NULL;
    }

    if (msg->req_formlist) {
        arr_pop_free(msg->req_formlist, http_form_free);
        msg->req_formlist = NULL;
    }

    if (msg->req_form_kvobj) {
        kvpair_clean(msg->req_form_kvobj);
        msg->req_form_kvobj = NULL;
    }

    if (msg->req_form_json) {
        json_clean(msg->req_form_json);
        msg->req_form_json = NULL;
    }

    if (msg->req_query_kvobj) {
        kvpair_clean(msg->req_query_kvobj);
        msg->req_query_kvobj = NULL;
    }

    if (msg->partial_list) {
        vstar_free(msg->partial_list);
        msg->partial_list = NULL;
    }

    if (msg->fwdurl) {
        k_mem_free(msg->fwdurl, msg->alloctype, msg->kmemblk);  
        msg->fwdurl = NULL;
    }
    msg->fwdurllen = 0;

    /* clear the buffer/data management resources which handle the http response */

    if (msg->res_file_handle) {
        native_file_close(msg->res_file_handle);
        msg->res_file_handle = NULL;
    }
    if (msg->res_file_name) {
        k_mem_free(msg->res_file_name, msg->alloctype, msg->kmemblk);
        msg->res_file_name = NULL;
    }
    if (msg->res_file_cache == 1) {
        //unlink(msg->res_file_name);
    }

    if (msg->res_cache_info) {
        cache_info_close(msg->res_cache_info);
        msg->res_cache_info = NULL;
    }

    /* Recycle all header-units and release resources */
    http_header_delall(msg, 1);

    if (msg->res_header_table) {
        ht_free(msg->res_header_table);
        msg->res_header_table = NULL;
    }

    if (msg->res_header_list) {
        arr_free(msg->res_header_list);
        msg->res_header_list = NULL;
    }

    if (msg->res_header_stream) {
        frame_delete(&msg->res_header_stream);
        msg->res_header_stream = NULL;
    }
    if (msg->res_body_stream) {
        frame_delete(&msg->res_body_stream);
        msg->res_body_stream = NULL;
    }
    if (msg->res_stream) {
        frame_delete(&msg->res_stream);
        msg->res_stream = NULL;
    }

    if (msg->res_chunk) {
        http_chunk_free(msg->res_chunk);
        msg->res_chunk = NULL;
    }

    if (msg->res_body_chunk) {
        chunk_free(msg->res_body_chunk);
        msg->res_body_chunk = NULL;
    }

    if (msg->res_rcvs_list) {
        arr_pop_free(msg->res_rcvs_list, frame_free);
        msg->res_rcvs_list = NULL;
    }

    msg->res_file_cache = 0;
    msg->res_store_file = NULL;
    msg->res_store_offset = 0;

    msg->res_recv_procnotify = NULL;
    msg->res_recv_procnotify_para = NULL;
    msg->res_recv_procnotify_cbval= 0;

    msg->req_send_procnotify = NULL;
    msg->req_send_procnotify_para = NULL;
    msg->req_send_procnotify_cbval = 0;

    if (msg->kmemblk) {
        kemblk_free(msg->kmemblk);
        msg->kmemblk = NULL;
    }

    return 0;
}


int http_msg_init_method (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;

    msg->SetTearDownNotify = http_msg_set_teardown_notify;
    msg->SetResponseNotify = http_msg_set_response_notify;

    msg->SetResStoreFile = http_msg_set_res_store_file;
    msg->SetResRecvAllNotify = http_msg_set_res_recvall_notify;
    msg->SetResRecvProcNotify = http_msg_set_res_recvproc_notify;
    msg->SetReqSendProcNotify = http_msg_set_req_sendproc_notify;

    msg->GetMIME = http_msg_get_mime;
    msg->GetMIMEMgmt = http_msg_get_mimemgmt;

    msg->GetEPump = GetEPump;
    msg->GetHTTPMgmt = GetHTTPMgmt;

    msg->GetCBObj = http_msg_cbobj;
    msg->GetMgmtObj = http_msg_mgmtobj;
    msg->GetMsgObj = http_msg_obj;
    msg->GetIODev = GetIODev;

    msg->GetFrame = GetFrame;
    msg->RecycleFrame = RecycleFrame;

    msg->Fetch = http_msg_newmsg;
    msg->Init = http_msg_init;
    msg->InitReq = http_msg_init_req;
    msg->InitRes = http_msg_init_res;
    msg->Recycle = http_msg_recycle;
    msg->Close = http_msg_closeit;

    msg->CacheType = http_msg_cache_type;
    msg->CacheFile = http_msg_cache_file;

    msg->GetSrcIP = http_msg_srcip;
    msg->GetSrcPort = http_msg_srcport;
    msg->GetMsgID = http_msg_id;
    msg->GetMethod = GetMethod;
    msg->GetMethodInd = GetMethodInd;
    msg->SetMethod = http_req_set_reqmeth;

    msg->GetURL = GetURL;
    msg->SetURL = http_req_set_uri;
    msg->GetDocURL = GetDocURL;
    msg->SetDocURL = http_req_set_docuri;
    msg->GetBaseURL = GetBaseURL;
    msg->GetAbsURL = GetAbsURL;
    msg->GetRelativeURL = GetRelative;

    msg->GetSchemeP = GetSchemeP;
    msg->GetScheme = GetScheme;
    msg->GetHostP = GetHostP;
    msg->GetHost = GetHost;
    msg->GetPort = GetPort;
    msg->GetPathP = GetPathP;
    msg->GetPath = GetReqPath;

    msg->GetRootPath = GetRootPath;

    msg->GetRealPath = GetRealPath;
    msg->GetRealFile = GetRealFile;
    msg->GetLocFile = GetLocFile;
    msg->GetPathOnly = GetPathOnly;
    msg->GetFileOnly = GetFileOnly;
    msg->GetFileExt = GetFileExt;

    msg->GetQueryP = GetQueryP;
    msg->GetQuery = GetQuery;
    msg->GetQueryValueP = GetQueryValueP;
    msg->GetQueryValue = GetQueryValue;
    msg->GetQueryUint = GetQueryUint;
    msg->GetQueryInt = GetQueryInt;
    msg->GetQueryUlong = GetQueryUlong;
    msg->GetQueryLong = GetQueryLong;
    msg->GetQueryInt64 = GetQueryInt64;
    msg->GetQueryUint64 = GetQueryUint64;
    msg->GetQueryKeyExist = GetQueryKeyExist;

    msg->GetReqFormJsonValueP = GetReqFormJsonValueP;
    msg->GetReqFormJsonValue = GetReqFormJsonValue;
    msg->GetReqFormJsonKeyExist = GetReqFormJsonKeyExist;

    msg->GetReqContentP = GetReqContentP;
    msg->GetReqContent = GetReqContent;

    msg->GetReqFormDecodeValue = GetReqFormDecodeValue;

    msg->GetReqFormValueP = GetReqFormValueP;
    msg->GetReqFormValue = GetReqFormValue;
    msg->GetReqFormUint = GetReqFormUint;
    msg->GetReqFormInt = GetReqFormInt;
    msg->GetReqFormUlong = GetReqFormUlong;
    msg->GetReqFormLong = GetReqFormLong;
    msg->GetReqFormUint64 = GetReqFormUint64;
    msg->GetReqFormKeyExist = GetReqFormKeyExist;

    msg->GetReqHdrNum = GetReqHdrNum;
    msg->GetReqHdrIndP = GetReqHdrIndP;
    msg->GetReqHdrInd = GetReqHdrInd;
    msg->GetReqHdrP = GetReqHdrP;
    msg->GetReqHdr = GetReqHdr;
    msg->GetReqHdrInt = GetReqHdrInt;
    msg->GetReqHdrLong = GetReqHdrLong;
    msg->GetReqHdrUlong = GetReqHdrUlong;
    msg->GetReqHdrInt64 = GetReqHdrInt64;
    msg->GetReqHdrUint64 = GetReqHdrUint64;

    msg->GetReqContentTypeP = GetReqContentTypeP;
    msg->GetReqContentType = GetReqContentType;
    msg->GetReqContentLength = GetReqContentLength;
    msg->GetReqEtag = GetReqEtag;
    msg->GetCookieP = GetCookieP;
    msg->GetCookie = GetCookie;

    msg->ParseReqMultipartForm = http_form_multipart_parse;
    msg->DisplayDirectory = DisplayDirectory;

    msg->AddReqHdr = AddReqHdr;
    msg->AddReqHdrInt = AddReqHdrInt;
    msg->AddReqHdrUint32 = AddReqHdrUint32;
    msg->AddReqHdrLong = AddReqHdrLong;
    msg->AddReqHdrUlong = AddReqHdrUlong;
    msg->AddReqHdrInt64 = AddReqHdrInt64;
    msg->AddReqHdrUint64 = AddReqHdrUint64;
    msg->AddReqHdrDate = AddReqHdrDate;
    msg->DelReqHdr = DelReqHdr ;

    msg->SetReqContentType = SetReqContentType;
    msg->SetReqContentLength = SetReqContentLength;
    msg->SetReqContent = SetReqContent;
    msg->SetReqFileContent = SetReqFileContent;

    msg->AddReqContent = AddReqContent;
    msg->AddReqContentPtr = AddReqContentPtr;
    msg->AddReqFile = AddReqFile;
    msg->AddReqAppCBContent = AddReqAppCBContent;

    /* the API operating the HTTP Response */
    msg->GetStatus = GetStatus;
    msg->GetResHdrNum = GetResHdrNum;
    msg->GetResHdrIndP = GetResHdrIndP;
    msg->GetResHdrInd =GetResHdrInd ;
    msg->GetResHdrP = GetResHdrP;
    msg->GetResHdr = GetResHdr;

    msg->GetResHdrInt = GetResHdrInt;
    msg->GetResHdrLong = GetResHdrLong;
    msg->GetResHdrUlong = GetResHdrUlong;
    msg->GetResHdrInt64 = GetResHdrInt64;
    msg->GetResHdrUint64 = GetResHdrUint64;

    msg->GetResContentTypeP = GetResContentTypeP;
    msg->GetResContentType = GetResContentType;
    msg->GetResContentTypeID = GetResContentTypeID;
    msg->GetResContentLength = GetResContentLength;

    msg->GetResContent = GetResContent;
    msg->GetResContentP = GetResContentP;

    msg->SetStatus = SetStatus;
    msg->AddResHdr = AddResHdr;
    msg->AddResHdrInt = AddResHdrInt;
    msg->AddResHdrUint32 = AddResHdrUint32;
    msg->AddResHdrLong = AddResHdrLong;
    msg->AddResHdrUlong = AddResHdrUlong;
    msg->AddResHdrInt64 = AddResHdrInt64;
    msg->AddResHdrUint64 = AddResHdrUint64;
    msg->AddResHdrDate = AddResHdrDate;
    msg->DelResHdr = DelResHdr;

    msg->SetResEtag = SetResEtag;
    msg->SetCookie = SetCookie;
    msg->SetResContentType = SetResContentType;
    msg->SetResContentTypeID = SetResContentTypeID;
    msg->SetResContentLength = SetResContentLength;

    msg->Check304Resp = Check304Resp;

    msg->AddResContent = AddResContent;
    msg->AddResStripContent = AddResStripContent;
    msg->AddResContentPtr = AddResContentPtr;
    msg->AddResFile = AddResFile;
    msg->AddResAppCBContent = AddResAppCBContent;

    msg->AddResTpl = http_pagetpl_add;
    msg->AddResTplFile = http_pagetpl_add_file;

    msg->RedirectReply = RedirectReply;
    msg->AsynReply = AsynReply;
    msg->Reply = Reply;
    msg->ReplyFeeding = ReplyFeeding;

    return 0;
}

int http_msg_init (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    
    if (!msg) return -1;

    mgmt = (HTTPMgmt *)gp_httpmgmt;

    if (mgmt->msg_kmem_pool && (msg->kmemblk = mpool_fetch(mgmt->msgmem_pool))) {
        kemblk_init(mgmt->msg_kmem_pool, msg->kmemblk, mpool_unitsize(mgmt->msgmem_pool), 1);
        msg->alloctype = 3;
    } else {
        msg->alloctype = 0;
        msg->kmemblk = NULL;
    }

    msg->msgtype = 0;
    msg->recycled = 0;

    msg->hl = NULL;
    msg->hc = NULL;
    msg->phost = NULL;
    msg->ploc = NULL;
    msg->locinst_times = 0;
    msg->matchnum = 0;
    memset(msg->matchstr, 0, sizeof(msg->matchstr));

    msg->cbobj = NULL;

    msg->script_var_tab = ht_only_alloc(23, var_obj_cmp_name, msg->alloctype, msg->kmemblk);

    msg->state = HTTP_MSG_NULL;
    msg->stamp = time(NULL);
    btime(&msg->createtime);

    msg->ssl_link = 0;

    http_msg_init_req(msg);

    msg->pcon = NULL;
    msg->conid = 0;

    msg->workerid = 0;

    msg->redirected = 0;

    /* proxy setting clear */
    msg->proxied = 0;
    msg->cacheon = 0;
    msg->proxymsg = NULL;
    msg->proxymsgid = 0;
    msg->proxy = NULL;
    msg->proxyport = 0;

    msg->fwdurl = NULL;
    msg->fwdurllen = 0;

    /* fastcgi setting clear */
    msg->fastcgi = 0;
    msg->fcgimsg = NULL;
    msg->fcgi_resend = 0;

    msg->partial_flag = 0;
    msg->partial_list = vstar_alloc(sizeof(http_partial_t), 2, NULL, msg->alloctype, msg->kmemblk);

    msg->flag304 = 0;
    msg->req_encoded = 0;
    msg->res_encoded = 0;

    http_msg_init_res(msg);

    msg->httpsrv = NULL;

    msg->resnotify = NULL;
    msg->resnotify_called = 0;
    msg->resnotify_para = NULL;
    msg->resnotify_cbval = NULL;
 
    msg->res_store_file = NULL;
    msg->res_store_offset = 0;
 
    msg->res_recv_procnotify = NULL;
    msg->res_recv_procnotify_para = NULL;
    msg->res_recv_procnotify_cbval = 0;

    msg->req_send_procnotify = NULL;
    msg->req_send_procnotify_para = NULL;
    msg->req_send_procnotify_cbval = 0;

    msg->tear_down_notify = NULL;
    msg->tear_down_para = NULL;

    memset(&msg->extdata[0], 0, mgmt->msgextsize);

    return 0;
}


int http_msg_recycle (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    HTTPMsg  * proxymsg = NULL;

    if (!msg) return -1;

    ++msg->recycled;

    if (msg->proxied > 0 && (proxymsg = msg->proxymsg)) {
        if (proxymsg->proxied > 0 && proxymsg->proxymsg == msg) {
            proxymsg->proxymsg = NULL;
        }
        msg->proxymsg = NULL;
    }

    msg->hl = NULL;
    msg->hc = NULL;
    msg->phost = NULL;
    msg->ploc = NULL;
    msg->matchnum = 0;
    memset(msg->matchstr, 0, sizeof(msg->matchstr));

    msg->cbobj = NULL;

    if (msg->script_var_tab) {
        ht_free_all(msg->script_var_tab, var_obj_free);
        msg->script_var_tab = NULL;
    }

    if (msg->resnotify && !msg->resnotify_called) {
        (*msg->resnotify)(msg, msg->resnotify_para, msg->resnotify_cbval, msg->res_status);
        msg->resnotify_called = 1;
    }

    if (msg->pcon) {
        http_con_msg_del(msg->pcon, msg);
        msg->pcon = NULL;
    }

    mgmt = (HTTPMgmt *)gp_httpmgmt;
    if (!mgmt || !mgmt->msg_pool)
        return -10;

    msg->state = HTTP_MSG_NULL;

    /* clear the buffer/data management resources which handle the http request */
    if (msg->uri) {
        http_uri_free(msg->uri);
        msg->uri = NULL;
    }
    if (msg->absuri) {
        http_uri_free(msg->absuri);
        msg->absuri = NULL;
    }
    if (msg->docuri) {
        http_uri_free(msg->docuri);
        msg->docuri = NULL;
    }

    if (msg->req_file_handle) {
        native_file_close(msg->req_file_handle);
        msg->req_file_handle = NULL;
    }
    if (msg->req_file_name) {
        unlink(msg->req_file_name);
        msg->req_file_cache = 0;

        k_mem_free(msg->req_file_name, msg->alloctype, msg->kmemblk);
        msg->req_file_name = NULL;
    }
    msg->req_multipart = 0;

    http_req_delallcookie(msg);
    http_header_delall(msg, 0);

    if (msg->req_cookie_table) {
        ht_free(msg->req_cookie_table);
        msg->req_cookie_table = NULL;
    }

    if (msg->req_header_table) {
        ht_free(msg->req_header_table);
        msg->req_header_table = NULL;
    }

    if (msg->req_header_list) {
        arr_free(msg->req_header_list);
        msg->req_header_list = NULL;
    }

    if (msg->req_header_stream) {
        frame_delete(&msg->req_header_stream);
        msg->req_header_stream = NULL;
    }
    if (msg->req_body_stream) {
        frame_delete(&msg->req_body_stream);
        msg->req_body_stream = NULL;
    }
    if (msg->req_stream) {
        frame_delete(&msg->req_stream);
        msg->req_stream = NULL;
    }

    if (msg->req_chunk) {
        http_chunk_free(msg->req_chunk);
        msg->req_chunk = NULL;
    }

    if (msg->req_body_chunk) {
        chunk_free(msg->req_body_chunk);
        msg->req_body_chunk = NULL;
    }

    if (msg->req_rcvs_list) {
        while (arr_num(msg->req_rcvs_list) > 0)
            frame_free(arr_pop(msg->req_rcvs_list));
        arr_free(msg->req_rcvs_list);
        msg->req_rcvs_list = NULL;
    }

    if (msg->req_formlist) {
        arr_pop_free(msg->req_formlist, http_form_free);
        msg->req_formlist = NULL;
    }

    if (msg->req_form_kvobj) {
        kvpair_clean(msg->req_form_kvobj);
        msg->req_form_kvobj = NULL;
    }

    if (msg->req_form_json) {
        json_clean(msg->req_form_json);
        msg->req_form_json = NULL;
    }

    if (msg->req_query_kvobj) {
        kvpair_clean(msg->req_query_kvobj);
        msg->req_query_kvobj = NULL;
    }

    if (msg->fwdurl) {
        k_mem_free(msg->fwdurl, msg->alloctype, msg->kmemblk);
        msg->fwdurl = NULL;
    }
    msg->fwdurllen = 0;

    if (msg->partial_list) {
        vstar_free(msg->partial_list);
        msg->partial_list = NULL;
    }

    /* clean the resources occupied by response */

    if (msg->res_file_handle) {
        native_file_close(msg->res_file_handle);
        msg->res_file_handle = NULL;
    }
    if (msg->res_file_name) {
        k_mem_free(msg->res_file_name, msg->alloctype, msg->kmemblk);
        msg->res_file_name = NULL;
    }
    if (msg->res_file_cache == 1) {
        //unlink(msg->res_file_name);
    }

    if (msg->res_cache_info) {
        cache_info_close(msg->res_cache_info);
        msg->res_cache_info = NULL;
    }

    /* Recycle all header-units and release resources */
    http_header_delall(msg, 1);

    if (msg->res_header_table) {
        ht_free(msg->res_header_table);
        msg->res_header_table = NULL;
    }

    if (msg->res_header_list) {
        arr_free(msg->res_header_list);
        msg->res_header_list = NULL;
    }

    if (msg->res_header_stream) {
        frame_delete(&msg->res_header_stream);
        msg->res_header_stream = NULL;
    }
    if (msg->res_body_stream) {
        frame_delete(&msg->res_body_stream);
        msg->res_body_stream = NULL;
    }
    if (msg->res_stream) {
        frame_delete(&msg->res_stream);
        msg->res_stream = NULL;
    }

    if (msg->res_chunk) {
        http_chunk_free(msg->res_chunk);
        msg->res_chunk = NULL;
    }

    if (msg->res_body_chunk) {
        chunk_free(msg->res_body_chunk);
        msg->res_body_chunk = NULL;
    }

    if (msg->res_rcvs_list) {
        while (arr_num(msg->res_rcvs_list) > 0)
            frame_free(arr_pop(msg->res_rcvs_list));
        arr_free(msg->res_rcvs_list);
        msg->res_rcvs_list = NULL;
    }

    msg->res_file_cache = 0;
    msg->cache_req_start = 0;
    msg->cache_req_off = 0;
    msg->cache_req_len = -1;

    if (msg->kmemblk) {
        kemblk_free(msg->kmemblk);
        mpool_recycle(mgmt->msgmem_pool, msg->kmemblk);
    }
    msg->kmemblk = NULL;

    mpool_recycle(mgmt->msg_pool, msg);
    return 0;
}

int http_msg_closeit (void * vmsg)
{
    return http_msg_close(vmsg);
}

int http_msg_close_dbg (void * vmsg, char * file, int line)
{
    HTTPMsg  * msg = (HTTPMsg *)vmsg;
    HTTPMgmt * mgmt = NULL;
    HTTPSrv  * srv = NULL;
    int        ret = 0;

    if (!msg) return -1;

    mgmt = (HTTPMgmt *)gp_httpmgmt;
    if (!mgmt) return -2;

    if (http_msg_mgmt_del(gp_httpmgmt, msg->msgid) != msg) {
        ret = -100;
    }

    if (ret < 0) goto cloexit;

    if ((srv = msg->httpsrv) != NULL) {
        srv->rtt = btime_diff_now(&msg->createtime);
    }

    /* write http access log to file */
    http_log_write(msg);

    http_msg_recycle(msg);

cloexit:
    return ret;
}


int http_msg_init_req (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    
    if (!msg) return -1;
    
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    
    memset(&msg->srcip, 0, sizeof(msg->srcip));
    msg->srcport = 0;
    memset(&msg->dstip, 0, sizeof(msg->dstip));
    msg->dstport = 0;

    msg->reqsent = 0;
    msg->req_gotall_body = 0;
    msg->redirecttimes = 0;
    msg->req_url_type = 0;

    msg->req_methind = HTTP_METHOD_NONE;
    memset(msg->req_meth, 0, sizeof(msg->req_meth));
    memset(msg->req_ver, 0, sizeof(msg->req_ver));
    msg->req_ver_major = 0;
    msg->req_ver_minor = 0;

    msg->uri = http_uri_alloc(msg->alloctype, msg->kmemblk);
    msg->absuri = http_uri_alloc(msg->alloctype, msg->kmemblk);
    msg->docuri = http_uri_alloc(msg->alloctype, msg->kmemblk);

    msg->pathhash = 0;
    msg->urihash = 0;

    msg->req_scheme = NULL;
    msg->req_schemelen = 0;
    msg->req_host = NULL;
    msg->req_hostlen = 0;
    msg->req_port = 0;
    msg->req_path = NULL;
    msg->req_pathlen = 0;
    msg->req_query = NULL;
    msg->req_querylen = 0;

    msg->req_line = NULL;
    msg->req_line_len = 0;
    msg->req_content_type = NULL;
    msg->req_contype_len = 0;
    msg->req_useragent = NULL;
    msg->req_useragent_len = 0;
    msg->req_cookie = NULL;
    msg->req_cookie_len = 0;

    /* the location of the end of http request header */
    msg->req_body_flag = 0;

    msg->req_header_length = 0;
    msg->req_body_length = 0;
    msg->req_body_iolen = 0;

    msg->req_conn_keepalive = 0;

    /* temperory file for storing request */
    msg->req_multipart = 0;
    msg->req_file_cache = 0;
    msg->req_file_name = NULL;
    msg->req_file_handle = NULL;

    msg->req_header_table = ht_only_alloc(mgmt->header_num, hunit_cmp_key, msg->alloctype, msg->kmemblk);
    hunit_set_hashfunc(msg->req_header_table);

    msg->req_cookie_table = ht_only_alloc(mgmt->header_num, hunit_cmp_key, msg->alloctype, msg->kmemblk);
    hunit_set_hashfunc(msg->req_cookie_table);

    msg->req_header_list = arr_alloc(16, msg->alloctype, msg->kmemblk);

    msg->req_header_stream = frame_alloc(0, msg->alloctype, msg->kmemblk);
    msg->req_body_stream = frame_alloc(0, msg->alloctype, msg->kmemblk);
    msg->req_stream = frame_alloc(0, msg->alloctype, msg->kmemblk);

    msg->req_chunk = NULL;

    msg->req_body_chunk = chunk_alloc(8192, msg->alloctype, msg->kmemblk);

    msg->req_rcvs_list = arr_alloc(2, msg->alloctype, msg->kmemblk);

    msg->req_formlist = arr_alloc(4, msg->alloctype, msg->kmemblk);
    msg->req_form_kvobj = NULL;
    msg->req_form_json = NULL;

    msg->req_query_kvobj = NULL;

    msg->req_stream_sent = 0;
    msg->req_stream_recv = 0;

    return 0;
}

int http_msg_init_res (void * vmsg)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    
    if (!msg) return -1;
    
    mgmt = (HTTPMgmt *)msg->httpmgmt;
    
    msg->res_ver[0] = '\0';
    msg->res_status = -500;
    msg->res_reason[0] = '\0';

    msg->res_mime = NULL;
    msg->res_mimeid = 0;

    msg->res_header_length = 0;
    msg->res_body_length = 0;
    msg->res_body_iolen = 0;

    msg->res_body_flag = BC_CONTENT_LENGTH;

    msg->res_gotall_body = 0;

    msg->res_conn_keepalive = 0;

    msg->res_file_handle = NULL;
    msg->res_file_name = NULL;

    msg->res_cache_info = NULL;

    msg->res_file_cache = 0;
    msg->cache_req_start = 0;
    msg->cache_req_off = 0;
    msg->cache_req_len = -1;

    msg->res_header_table = ht_only_alloc(mgmt->header_num, hunit_cmp_key, msg->alloctype, msg->kmemblk);
    hunit_set_hashfunc(msg->res_header_table);

    msg->res_header_list = arr_alloc(16, msg->alloctype, msg->kmemblk);
    
    msg->res_header_stream = frame_alloc(0, msg->alloctype, msg->kmemblk);
    msg->res_body_stream = frame_alloc(0, msg->alloctype, msg->kmemblk);
    msg->res_stream = frame_alloc(0, msg->alloctype, msg->kmemblk);

    msg->res_chunk = NULL;

    msg->res_body_chunk = chunk_alloc(8192, msg->alloctype, msg->kmemblk);

    msg->res_stream_sent = 0;
    msg->res_stream_recv = 0;

    msg->res_rcvs_list = arr_alloc(4, msg->alloctype, msg->kmemblk);

    return 0;
}


void * http_msg_cbobj (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return NULL;

    return msg->cbobj;
}

void * http_msg_obj (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;
        
    if (!msg) return NULL; 

    return &msg->extdata[0];
}

void * http_msg_mgmtobj (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;
        
    if (!msg) return NULL; 

    return http_mgmt_obj(msg->httpmgmt);
}

char * http_msg_get_mime (void * vmsg, char * extname, uint32 * mimeid)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;
        
    if (!msg) return "application/octet-stream"; 

    return http_get_mime(msg->httpmgmt, extname, mimeid);
}

void * http_msg_get_mimemgmt (void * vmsg)
{
    HTTPMsg  * msg = (HTTPMsg *) vmsg;
    HTTPMgmt * mgmt = NULL;
        
    if (!msg) return NULL; 

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return NULL;

    return mgmt->mimemgmt;
}


void * http_msg_newmsg (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;
        
    if (!msg) return NULL; 

    return http_msg_fetch(msg->httpmgmt);
}


char * http_msg_srcip (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return "";

    return msg->srcip;
}

int http_msg_srcport (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return 0;

    return msg->srcport;
}

ulong http_msg_id (void * vmsg)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return 0;

    return msg->msgid;
}

int http_msg_set_teardown_notify (void * vmsg, void * func, void * para)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return -1;

    msg->tear_down_notify = func;
    msg->tear_down_para = para;

    return 0;
}

int http_msg_set_response_notify (void * vmsg, void * func, void * para, void * cbval,
                                  char * storefile, int64 offset,
                                  void * procnotify, void * procpara, uint64 proccbval)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return -1;

    msg->resnotify = func;
    msg->resnotify_called = 0;
    msg->resnotify_para = para;
    msg->resnotify_cbval = cbval;

    msg->res_store_file = storefile;
    msg->res_store_offset = offset;

    msg->res_recv_procnotify = procnotify;
    msg->res_recv_procnotify_para = procpara;
    msg->res_recv_procnotify_cbval = proccbval;

    return 0;
}

int http_msg_set_res_recvall_notify (void * vmsg, void * func, void * para, void * cbval)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return -1;

    msg->resnotify = func;
    msg->resnotify_called = 0;
    msg->resnotify_para = para;
    msg->resnotify_cbval = cbval;

    return 0;
}

int http_msg_set_res_store_file (void * vmsg, char * storefile, int64 offset)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return -1;

    msg->res_store_file = storefile;
    msg->res_store_offset = offset;

    return 0;
}

int http_msg_set_res_recvproc_notify (void * vmsg, void * procnotify, void * procpara, uint64 proccbval)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return -1;

    msg->res_recv_procnotify = procnotify;
    msg->res_recv_procnotify_para = procpara;
    msg->res_recv_procnotify_cbval = proccbval;

    return 0;
}

int http_msg_set_req_sendproc_notify (void * vmsg, void * procnotify, void * procpara, uint64 proccbval)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return -1;

    msg->req_send_procnotify = procnotify;
    msg->req_send_procnotify_para = procpara;
    msg->req_send_procnotify_cbval = proccbval;

    return 0;
}

/* 1 - temporary cache file
   2 - application-given file for storing response body
   3 - proxy cache file with partial content
   4 - proxy cache file will all content */
int http_msg_cache_type (void * vmsg, int respornot)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return 0;

    if (respornot) {
        return msg->res_file_cache;
    } else {
        return msg->req_file_cache;
    }

    return 0;
}

char * http_msg_cache_file (void * vmsg, int respornot)
{
    HTTPMsg * msg = (HTTPMsg *) vmsg;

    if (!msg) return NULL;

    if (respornot) {
        if (msg->res_file_cache == 1) return msg->res_file_name;
        if (msg->res_file_cache == 2) return msg->res_store_file;
    } else {
        if (msg->req_file_cache == 1) return msg->req_file_name;
    }

    return NULL;
}


int http_msg_mgmt_add (void * vmgmt, void * vmsg)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg    * pmsg = (HTTPMsg *)vmsg;

    if (!mgmt) return -1;
    if (!pmsg) return -2;

    EnterCriticalSection(&mgmt->msgtableCS);
    ht_set(mgmt->msg_table, (void *)pmsg->msgid, pmsg);
    LeaveCriticalSection(&mgmt->msgtableCS);

    return 0;
}

void * http_msg_mgmt_get (void * vmgmt, ulong msgid)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg    * pmsg = NULL;

    if (!mgmt) return NULL;

    EnterCriticalSection(&mgmt->msgtableCS);
    pmsg = ht_get(mgmt->msg_table, (void *)msgid);
    LeaveCriticalSection(&mgmt->msgtableCS);

    return pmsg;
}

void * http_msg_mgmt_del (void * vmgmt, ulong msgid)
{
    HTTPMgmt   * mgmt = (HTTPMgmt *)vmgmt;
    HTTPMsg    * pmsg = NULL;

    if (!mgmt) return NULL;

    EnterCriticalSection(&mgmt->msgtableCS);
    pmsg = ht_delete(mgmt->msg_table, (void *)msgid);
    LeaveCriticalSection(&mgmt->msgtableCS);

    return pmsg;
}


int http_msg_var_set (void * vmsg, char * name, char * value, int valuelen)
{
    HTTPMsg   * msg = (HTTPMsg *)vmsg;
    var_obj_t * obj = NULL;
    int         namelen = 0;

    if (!msg) return -1;
    if (!name) return -2;

    namelen = str_len(name);
    if (namelen <= 0) return -3;

    if (value && valuelen < 0)
        valuelen = strlen(value);

    obj = ht_get(msg->script_var_tab, name);
    if (!obj) {
        obj = var_obj_alloc(msg->alloctype, msg->kmemblk);
        
        obj->name = k_mem_str_dup(name, namelen, msg->alloctype, msg->kmemblk);
        obj->namelen = namelen;

        ht_set(msg->script_var_tab, name, obj);

    } else {
        if (obj->value) {
            //kfree(obj->value);
            k_mem_free(obj->value, msg->alloctype, msg->kmemblk);
            obj->value = NULL;
        }
        obj->valuelen = 0;
    }

    if (value && valuelen >= 0)
        obj->value = k_mem_str_dup(value, valuelen, msg->alloctype, msg->kmemblk);
     obj->valuelen = valuelen;

    return 0;
}

int http_msg_var_get (void * vmsg, char * name, char * value, int valuelen)
{
    HTTPMsg   * msg = (HTTPMsg *)vmsg;
    var_obj_t * obj = NULL;
    int         len = 0;

    if (!msg) return -1;
    if (!name) return -2;

    len = str_len(name);
    if (len <= 0) return -3;

    obj = ht_get(msg->script_var_tab, name);
    if (!obj) {
        return -100;
    }

    len = obj->valuelen;
    if (value && valuelen > 0) {
        if (len > valuelen) len = valuelen;
        str_secpy(value, valuelen, obj->value, len);
        return len;
    }

    return len;
}

