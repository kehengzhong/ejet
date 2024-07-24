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

#include "http_mgmt.h"
#include "http_msg.h"
#include "http_header.h"
#include "http_request.h"
#include "http_resloc.h"
#include "http_cache.h"
#include "http_script.h"
#include "http_variable.h"


int http_var_cmp_name (void * a, void * b)
{
    http_var_t  * var = (http_var_t *)a;
    char        * vname = (char *)b;

    return str_casecmp(var->varname, vname);
}

void http_var_name (http_var_t * var, char * vname)
{
    int  len = 0;

    if (!var || !vname) return;

    len = strlen(vname);
    if (len <= 0) return;

    str_secpy(var->varname, sizeof(var->varname)-1, vname, len);
}


int http_var_init (void * vmgmt)
{
    HTTPMgmt    * mgmt = (HTTPMgmt *)vmgmt;
    http_var_t  * var = NULL;
    int           i, ind = 0;

    if (!mgmt) return -1;

    mgmt->varsize = 72;

    mgmt->variable = var = kzalloc(mgmt->varsize * sizeof(http_var_t));

    //0-char 1-short 2-int 3-char[] 

    http_var_name(&var[ind], "remote_addr");
    http_var_set6(&var[ind], HTTPMsg, srcip, dstip, 4, 0);
    ind++;

    http_var_name(&var[ind], "remote_port");
    http_var_set6(&var[ind], HTTPMsg, srcport, dstport, 2, 0);
    ind++;

    http_var_name(&var[ind], "server_addr");
    http_var_set(&var[ind], HTTPMsg, dstip, 4, 0, 0);
    ind++;

    http_var_name(&var[ind], "server_port");
    http_var_set(&var[ind], HTTPMsg, req_port, 2, 0, 0);
    ind++;

    http_var_name(&var[ind], "request_method");
    http_var_set(&var[ind], HTTPMsg, req_meth, 4, 0, 0);
    ind++;

    http_var_name(&var[ind], "scheme");
    http_var_set2(&var[ind], HTTPMsg, req_scheme, req_schemelen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "host_name");
    http_var_set2(&var[ind], HTTPMsg, req_host, req_hostlen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "request_path");
    http_var_set2(&var[ind], HTTPMsg, req_path, req_pathlen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "query_string");
    http_var_set2(&var[ind], HTTPMsg, req_query, req_querylen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "req_path_only");
    http_var_set5(&var[ind], HTTPMsg, docuri, HTTPUri, dir, dirlen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "req_file_only");
    http_var_set5(&var[ind], HTTPMsg, docuri, HTTPUri, file, filelen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "req_file_base");
    http_var_set5(&var[ind], HTTPMsg, docuri, HTTPUri, file_base, file_baselen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "req_file_ext");
    http_var_set5(&var[ind], HTTPMsg, docuri, HTTPUri, file_ext, file_extlen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "real_file");
    http_var_set3(&var[ind], 8, 0);
    ind++;

    http_var_name(&var[ind], "real_path");
    http_var_set3(&var[ind], 8, 0);
    ind++;

    http_var_name(&var[ind], "bytes_recv");
    http_var_set6(&var[ind], HTTPMsg, req_stream_recv, res_stream_recv, 3, 0);
    ind++;

    http_var_name(&var[ind], "bytes_sent");
    http_var_set6(&var[ind], HTTPMsg, res_stream_sent, req_stream_sent, 3, 0);
    ind++;

    http_var_name(&var[ind], "status");
    http_var_set(&var[ind], HTTPMsg, res_status, 2, 0, 0);
    ind++;

    http_var_name(&var[ind], "mime");
    http_var_set(&var[ind], HTTPMsg, res_mime, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "mimeid");
    http_var_set(&var[ind], HTTPMsg, res_mimeid, 2, 1, 0);
    ind++;

    http_var_name(&var[ind], "document_root");
    http_var_set(&var[ind], HTTPLoc, root, 4, 0, 2);
    ind++;

    http_var_name(&var[ind], "fastcgi_script_name");
    http_var_set5(&var[ind], HTTPMsg, docuri, HTTPUri, path, pathlen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "content_type");
    http_var_set2(&var[ind], HTTPMsg, req_content_type, req_contype_len, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "content_length");
    http_var_set(&var[ind], HTTPMsg, req_body_length, 3, 0, 0);
    ind++;

    http_var_name(&var[ind], "msgid");
    http_var_set(&var[ind], HTTPMsg, msgid, 3, 1, 0);
    ind++;

    http_var_name(&var[ind], "conid");
    http_var_set(&var[ind], HTTPMsg, conid, 3, 1, 0);
    ind++;

    http_var_name(&var[ind], "proxymsgid");
    http_var_set(&var[ind], HTTPMsg, proxymsgid, 3, 1, 0);
    ind++;

    http_var_name(&var[ind], "absuri");
    http_var_set4(&var[ind], HTTPMsg, absuri, HTTPUri, uri, 6, 0, 0);
    ind++;

    http_var_name(&var[ind], "uri");
    http_var_set5(&var[ind], HTTPMsg, uri, HTTPUri, path, pathlen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "request_uri");
    http_var_set4(&var[ind], HTTPMsg, uri, HTTPUri, uri, 6, 0, 0);
    ind++;

    http_var_name(&var[ind], "document_uri");
    http_var_set5(&var[ind], HTTPMsg, docuri, HTTPUri, path, pathlen, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "request");
    http_var_set2(&var[ind], HTTPMsg, req_line, req_line_len, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "http_user_agent");
    http_var_set2(&var[ind], HTTPMsg, req_useragent, req_useragent_len, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "http_cookie");
    http_var_set2(&var[ind], HTTPMsg, req_cookie, req_cookie_len, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "server_protocol");
    http_var_set(&var[ind], HTTPMgmt, httpver1, 4, 0, 1);
    ind++;

    http_var_name(&var[ind], "sys_status");
    http_var_set(&var[ind], HTTPMgmt, uptimestr, 4, 0, 1);
    ind++;

    http_var_name(&var[ind], "cache_maxage");
    http_var_set4(&var[ind], HTTPMsg, res_cache_info, CacheInfo, maxage, 2, 0, 0);
    ind++;

    http_var_name(&var[ind], "cache_revalidate");
    http_var_set4(&var[ind], HTTPMsg, res_cache_info, CacheInfo, revalidate, 0, 1, 0);
    ind++;

    http_var_name(&var[ind], "cache_file");
    http_var_set4(&var[ind], HTTPMsg, res_cache_info, CacheInfo, cache_file, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "cachetmp_file");
    http_var_set4(&var[ind], HTTPMsg, res_cache_info, CacheInfo, cache_tmp, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "cacheinfo_file");
    http_var_set4(&var[ind], HTTPMsg, res_cache_info, CacheInfo, info_file, 5, 0, 0);
    ind++;

    http_var_name(&var[ind], "ejet_version");
    http_var_global(&var[ind], g_http_version, 4, 0, 3);
    ind++;

    http_var_name(&var[ind], "request_header");
    var[ind].valtype = 7;  //array
    var[ind].arraytype = 1; //request header
    ind++;

    http_var_name(&var[ind], "cookie");
    var[ind].valtype = 7;  //array
    var[ind].arraytype = 2; //cookie
    ind++;

    http_var_name(&var[ind], "query");
    var[ind].valtype = 7;  //array
    var[ind].arraytype = 3; //query
    ind++;

    http_var_name(&var[ind], "response_header");
    var[ind].valtype = 7;  //array
    var[ind].arraytype = 4; //response header
    ind++;

    http_var_name(&var[ind], "datetime");
    var[ind].valtype = 7;  //array
    var[ind].arraytype = 5; //$datetime, $datetime[createtime], $datetime[stamp]
    ind++;

    http_var_name(&var[ind], "date");
    var[ind].valtype = 7;  //array 
    var[ind].arraytype = 6; //$date, $date[createtime], $date[stamp]
    ind++;

    http_var_name(&var[ind], "time");
    var[ind].valtype = 7;  //array 
    var[ind].arraytype = 7; //$time, $time[createtime], $time[stamp]
    ind++;

    http_var_name(&var[ind], "unixtime");
    var[ind].valtype = 7;  //array 
    var[ind].arraytype = 8; //$unixtime, $unixtime[createtime], $unixtime[stamp]
    ind++;

    http_var_name(&var[ind], "filemtime");
    var[ind].valtype = 7;  //array 
    var[ind].arraytype = 9; // $filemtime[filename]
    ind++;

    http_var_name(&var[ind], "filectime");
    var[ind].valtype = 7;  //array 
    var[ind].arraytype = 10; // $filectime[filename]
    ind++;

    http_var_name(&var[ind], "filesize");
    var[ind].valtype = 7;  //array 
    var[ind].arraytype = 11; // $filesize[filename]
    ind++;

    mgmt->varnum = ind;

    mgmt->var_table = ht_only_new(149, http_var_cmp_name);

    for (i = 0; i < ind; i++) {
        ht_set(mgmt->var_table, var[i].varname, &var[i]);
    }

    tolog(1, "eJet - %d HTTP Variables init successfully.\n", ind);
    return 0;
}

int http_var_free (void * vmgmt)
{
    HTTPMgmt    * mgmt = (HTTPMgmt *)vmgmt;
 
    if (!mgmt) return -1;
 
    if (mgmt->var_table) {
        ht_free(mgmt->var_table);
        mgmt->var_table = NULL;
    }

    kfree(mgmt->variable);

    tolog(1, "eJet - HTTP Variables freed.\n");
    return 0;
}

int http_var_value (void * vmsg, char * vname, char * buf, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HTTPLoc    * ploc = NULL;
    http_var_t * var = NULL;

    char         sbuf[128];
    char         varmain[128];
    char       * plist[4] = {NULL};
    int          plen[4] = {0};
    int          ret = 0;

    void       * obj = NULL;
    void       * subobj = NULL;
    void       * objlen = NULL;

    char       * pval = NULL;
    frame_p      frm = NULL;

    int          flen = 0;

    if (!msg) return -1;
    if (!vname || strlen(vname) <= 0) return -2;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -3;

    /* query [ fid ] */
    ret = string_tokenize(vname, -1, "[] \t\r\n", 6, (void **)plist, plen, 4);
    if (ret < 0) return -4;

    str_secpy(varmain, sizeof(varmain)-1, plist[0], plen[0]);

    var = ht_get(mgmt->var_table, varmain);
    if (!var) return -100;

    /* if it's an array variable. eg. request_header[content-type] */
    if (var->valtype == 7) {
        switch (var->arraytype) {
        case 1:  //request header
            return http_var_header_value(msg, 0, plist[1], plen[1], buf, len);

        case 2:  //cookie
            return http_var_cookie_value(msg, plist[1], plen[1], buf, len);

        case 3:  //query
            return http_var_query_value(msg, plist[1], plen[1], buf, len);

        case 4:  //response header
            return http_var_header_value(msg, 1, plist[1], plen[1], buf, len);

        case 5:  //$datetime, $datatime[createtime], $datetime[stamp]
        case 6:  //$date, $date[createtime], $date[stamp]
        case 7:  //$time, $time[createtime], $time[stamp]
        case 8:  //$unixtime, $unixtime[createtime], $unixtime[stamp]
            return http_var_datetime_value(msg, plist[1], plen[1], buf, len, var->arraytype);

        case 9:   //$filemtime[filename]
        case 10:  //$filectime[filename]
        case 11:  //$filesize[filename]
            return http_var_fileattr_value(msg, plist[1], plen[1], buf, len, var->arraytype);
        }
        return -110;
    }

    ploc = (HTTPLoc *)msg->ploc;
    if (!ploc && var->structtype == 2) return -4;

    if (var->structtype >= 0 && var->structtype <= 2) {
        if (var->structtype == 0)  //HTTPMsg 
            obj = (uint8 *)msg + var->fieldpos;
        else if (var->structtype == 1)  //HTTPMgmt 
            obj = (uint8 *)mgmt + var->fieldpos;
        else if (var->structtype == 2)  //HTTPLoc
            obj = (uint8 *)ploc + var->fieldpos;

        if (var->substruct) {
            subobj = * (void **)obj;
            if (subobj != NULL) {
                obj = (uint8 *)subobj + var->subfldpos;
                objlen = (uint8 *)subobj + var->subfldlenpos;
            } else {
                obj = NULL;
            }
        } else if (var->condcheck) {
            if (msg->msgtype == 0) {
                obj = (uint8 *)msg + var->subfldpos;
            }
        } else {
            if (var->haslen)
                objlen = (uint8 *)msg + var->fldlenpos;
        }
    } else if (var->structtype == 3) {  //global variable
        obj = var->field;
    }

    if (obj) {
        switch (var->valtype) {
        case 0:   //char
            if (var->unsign) {
                ret = sprintf(sbuf, "%d", *(uint8 *) obj );
            } else {
                ret = sprintf(sbuf, "%d", *(char *) obj );
            }

            if (buf) {
                str_secpy(buf, len, sbuf, ret);
                return strlen(buf);
            }
            return ret;

        case 1:   //short
            if (var->unsign) {
                ret = sprintf(sbuf, "%d", *(uint16 *) obj );
            } else {
                ret = sprintf(sbuf, "%d", *(int16 *) obj );
            }

            if (buf) {
                str_secpy(buf, len, sbuf, ret);
                return strlen(buf);
            }
            return ret;

        case 2:   //int
            if (var->unsign) {
                ret = sprintf(sbuf, "%u", *(uint32 *) obj );
            } else {
                ret = sprintf(sbuf, "%d", *(int *) obj );
            }

            if (buf) {
                str_secpy(buf, len, sbuf, ret);
                return strlen(buf);
            }
            return ret;

        case 3:   //int64
            if (var->unsign) {
#if defined(_WIN32) || defined(_WIN64)
                ret = sprintf(sbuf, "%I64u", *(uint64 *) obj );
#else
                ret = sprintf(sbuf, "%llu", *(uint64 *) obj );
#endif
            } else {
#if defined(_WIN32) || defined(_WIN64)
                ret = sprintf(sbuf, "%I64d", *(int64 *) obj );
#else
                ret = sprintf(sbuf, "%lld", *(int64 *) obj );
#endif
            }

            if (buf) {
                str_secpy(buf, len, sbuf, ret);
                return strlen(buf);
            }
            return ret;

        case 4:   //char []
            pval = (char *) obj;

            if (var->haslen)
                flen = *(int *) objlen;
            else
                flen = strlen((char *)pval);

            if (buf) {
                str_secpy(buf, len, (char *)pval, flen);
                return strlen(buf);
            }

            return flen;

        case 5:   //char *
            pval = *(char **) obj;
            if (!pval) return 0;
 
            if (var->haslen)
                flen = *(int *) objlen;
            else
                flen = strlen((char *)pval);
 
            if (buf) {
                str_secpy(buf, len, (char *)pval, flen);
                return strlen(buf);
            }
 
            return flen;

        case 6:   //frame_p
            frm = *(frame_p *) obj;
            if (!frm) return 0;

            if (buf) {
                str_secpy(buf, len, frame_string(frm), frameL(frm));
                return strlen(buf);
            }

            return frameL(frm);

        case 8:   //function
            if (str_casecmp(var->varname, "real_file") == 0) {
                return http_real_file(obj, buf, len);

            } else if (str_casecmp(var->varname, "real_path") == 0) {
                return http_real_path(obj, buf, len);
            }
            break;
        }
    }

    return -200;
}

int http_var_value_set (void * vmsg, char * vname, char * value, int vallen)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    HTTPLoc    * ploc = NULL;
    http_var_t * var = NULL;

    char         varmain[128];
    char       * plist[4] = {NULL};
    int          plen[4] = {0};
    int          ret = 0;

    void       * obj = NULL;
    void       * subobj = NULL;
    int          objsize = 0;

    int          ival = 0;
    int64        val64 = 0;

    if (!msg) return -1;
    if (!vname || strlen(vname) <= 0) return -2;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return -3;

    /* query [ fid ] */
    ret = string_tokenize(vname, -1, "[] \t\r\n", 6, (void **)plist, plen, 4);
    if (ret < 0) return -4;

    str_secpy(varmain, sizeof(varmain)-1, plist[0], plen[0]);

    var = ht_get(mgmt->var_table, varmain);
    if (!var) return -100;

    /* if it's an array variable. eg. request_header[content-type] */
    if (var->valtype == 7) {
        switch (var->arraytype) {
        case 1:  //request header
            return http_var_header_value_set(msg, 0, plist[1], plen[1], value, vallen);

        case 2:  //cookie
            return http_var_cookie_value_set(msg, plist[1], plen[1], value, vallen);

        case 3:  //query
            return http_var_query_value_set(msg, plist[1], plen[1], value, vallen);

        case 4:  //response header
            return http_var_header_value_set(msg, 1, plist[1], plen[1], value, vallen);
        }
        return -110;
    }

    ploc = (HTTPLoc *)msg->ploc;
    if (!ploc && var->structtype == 2) return -4;

    objsize = var->fieldsize;

    if (var->structtype >= 0 && var->structtype <= 2) {
        if (var->structtype == 0)  //HTTPMsg 
            obj = (uint8 *)msg + var->fieldpos;
        else if (var->structtype == 1)  //HTTPMgmt 
            obj = (uint8 *)mgmt + var->fieldpos;
        else if (var->structtype == 2)  //HTTPLoc
            obj = (uint8 *)ploc + var->fieldpos;

        if (var->substruct) {
            subobj = * (void **)obj;
            if (subobj != NULL) {
                obj = (uint8 *)subobj + var->subfldpos;
            } else {
                obj = NULL;
            }
        } else if (var->condcheck) {
            if (msg->msgtype == 0) {
                obj = (uint8 *)msg + var->subfldpos;
            }
        }
    } else if (var->structtype == 3) {  //global variable
        obj = var->field;
    }

    if (obj) {
        switch (var->valtype) {
        case 0:   //char
            str_atoi(value, vallen, &ival);
            
            if (var->unsign) {
                *(uint8 *)obj = ival;
            } else {
                *(char *)obj = ival;
            }
            return 1;

        case 1:   //short
            str_atoi(value, vallen, &ival);
            if (var->unsign) {
                *(uint16 *)obj = ival;
            } else {
                *(int16 *)obj = ival;
            }
            return 2;

        case 2:   //int
            str_atoll(value, vallen, &val64);
            if (var->unsign) {
                *(uint32 *) obj = (uint32)val64;
            } else {
                *(int *) obj = (int)val64;
            }
            return 4;

        case 3:   //int64
            str_atoll(value, vallen, &val64);
            if (var->unsign) {
                *(uint64 *)obj = val64;
            } else {
                *(int64 *)obj = val64;
            }
            return 8;

        case 4:   //char []
            return str_secpy((char *)obj, objsize, value, vallen);
        }
    }

    return -200;
}

static int is_var_char (int c)
{
    /*if ( (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c == '_') )
        return 1;*/

    if ( (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         ( c >= '0' && c <= '9') || (c == '_') )
        return 1;

    return 0;
}

int http_var_copy (void * vmsg, char * vstr, int vlen, char * buf, int buflen,
                   ckstr_t * pmat, int matnum, char * lastvname, int lasttype)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    HTTPLoc     * ploc = NULL;
    HTTPHost    * host = NULL;
    HTTPListen  * hl = NULL;
    HTTPConnect * hc = NULL;
    char          vname[128];
    int           ret, iter = 0;
    int           i, len = 0, matind = 0;
    int           retlen = 0;
    void        * jobj[4];
    int           jobjnum = 0;
    char        * pbgn = NULL;
    char        * pend = NULL;
    char        * pval = NULL;
    char        * poct = NULL;
    char        * pvarend = NULL;

    if (!msg) return -1;

    if (!vstr) return -2;
    if (vlen < 0) vlen = strlen(vstr);
    if (vlen <= 0) return -3;

    if (buf && buflen > 0) buf[0] = '\0';

    ploc = (HTTPLoc *)msg->ploc;
    host = (HTTPHost *)msg->phost;
    hl = (HTTPListen *)msg->hl;
    hc = (HTTPConnect *)msg->hc;

    jobjnum = 0;
    if (ploc) jobj[jobjnum++] = ploc->jsonobj;
    if (host) jobj[jobjnum++] = host->jsonobj;
    if (hl)   jobj[jobjnum++] = hl->jsonobj;
    if (hc)   jobj[jobjnum++] = hc->jsonobj;

    pbgn = vstr;
    pend = vstr + vlen;

    for (iter = 0; pbgn < pend; ) {

        if (buf && buflen > 0 && iter >= buflen)
            break;

        if (*pbgn == '$') {
            if (pbgn[1] == '{') {
                poct = skipToPeer(pbgn+1, pend-pbgn-1, '{', '}');
                if (!poct || poct >= pend) goto docopy;

                pbgn = skipOver(pbgn+2, poct-pbgn-2, " \t\r\n", 4);
                if (pbgn >= poct) { pbgn = poct + 1; continue; }

                /* ${ remote_addr }, or ${ query [ fid ] }, or ${1} */
                pvarend = rskipOver(poct-1, poct-pbgn, " \t\r\n", 4);
                
                str_secpy(vname, sizeof(vname)-1, pbgn, pvarend-pbgn+1);
                pbgn = poct + 1;

            } else {
               poct = pbgn + 1;
               /* variable name may be like: $1 $2 */
               while (is_var_char(*poct) && poct < pend) poct++;
               if (poct <= pbgn + 1) goto docopy;

                /* $request_header[accept] */
                if (poct < pend && *poct == '[') {
                    poct = skipTo(poct, pend-poct, "]", 1);
                    if (*poct == ']') poct++;
                }

                str_secpy(vname, sizeof(vname)-1, pbgn + 1, poct-pbgn-1);
                pbgn = poct;
            }

            /* first, check if the var-string exists numeric variable pointing to the input mating array,
               variable type: 1 */
            ret = strlen(vname);
            for (i = 0; i < ret && isdigit(vname[i]); i++);
            if (i >= ret) {  //all chars of variable name are digits
                if (!pmat || matnum <= 0) {
                    pmat = msg->matchstr;
                    matnum = msg->matchnum;
                }
                if (pmat && matnum > 0) {
                    matind = strtol(vname, NULL, 10);
                    if (matind < matnum) {
                        if (!buf)
                            iter += pmat[matind].len;
                        else 
                            iter += str_secpy(buf + iter, buflen - iter, pmat[matind].p, pmat[matind].len);
                        continue;
                    }
                }
            }

            /* second, check the dynamic temporary local variables set by scripts in configuration
                 variable type: 2 */
            if (buf && buflen > 0)
                ret = http_msg_var_get(msg, vname, buf + iter, buflen - iter);
            else
                ret = http_msg_var_get(msg, vname, NULL, 0);
            if (ret >= 0) {
                iter += ret;
                continue;
            }

            /* third, check global variables or HTTPMsg common parameters
                variable type: 3 */
            if (buf && buflen > 0) {
                buf[iter] = '\0';
                ret = http_var_value(msg, vname, buf + iter, buflen - iter);
            } else {
                ret = http_var_value(msg, vname, NULL, 0);
            }
            if (ret >= 0) iter += ret;

            /* at last, check the variables defined in Location, Host, Listen
                 variable type: 4 */
            if (lastvname && strcasecmp(vname, lastvname) == 0 && lasttype == 4)
                continue;;

            for (ret = 0, i = 0; i < jobjnum; i++) {
                ret = json_mgetP(jobj[i], vname, strlen(vname), (void **)&poct, &len);
                if (ret > 0) {
                    if (strncasecmp(poct, "<script>", 8) == 0) {
                        http_script_segment_exec(msg, poct, len, &pval, &retlen, vname, 4);
                        if (buf) {
                            if (pval && retlen > 0)
                                iter += str_secpy(buf + iter, buflen-iter, pval, retlen);
                        } else {
                            iter += retlen;
                        }
                        if (pval) kfree(pval);
                        break;

                    } else {
                        /* how to solve the recursive parsing is a problem.
                             $root = $root$path$fid$fileext; */
                        if (buf)
                            ret = http_var_copy(msg, poct, len, buf+iter, buflen-iter, NULL, 0, vname, 4);
                        else
                            ret = http_var_copy(msg, poct, len, NULL, 0, NULL, 0, vname, 4);
                        if (ret > 0) {
                            iter += ret;
                            break;
                        }
                    }
                }
            }

            continue;

        } else if (pend - pbgn >= 8 && strncasecmp(pbgn, "<script>", 8) == 0) {
            ret = http_script_segment_exec(msg, pbgn, pend - pbgn, &pval, &retlen, lastvname, lasttype);
            if (buf) {
                if (pval && retlen > 0)
                    iter += str_secpy(buf + iter, buflen-iter, pval, retlen);
            } else {
                iter += retlen;
            }
            if (pval) kfree(pval);

            pbgn += ret;

            continue;
        }

docopy:
        if (buf && buflen > 0) {
            buf[iter++] = *pbgn++;
        } else {
            iter++; pbgn++;
        }
    }

    if (buf && buflen > 0) buf[iter] = '\0';

    return iter;
}

void http_var_print (void * vmsg, char * varn, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HTTPMgmt   * mgmt = NULL;
    http_var_t * var = NULL;
    char         vname[64];
    char         buf[4096];
    int          i = 0;

    if (!msg) return;

    mgmt = (HTTPMgmt *)msg->httpmgmt;
    if (!mgmt) return;
    
    var = (http_var_t *)mgmt->variable;

    if (varn) {
        http_var_copy(msg, varn, len, buf, sizeof(buf)-1, NULL, 0, NULL, 0);
        printf("%s = %s\n", varn, buf);
        return;
    }

    for (i = 0; i < mgmt->varnum; i++) {
        sprintf(vname, "$%s", var[i].varname);

        http_var_copy(msg, vname, strlen(vname), buf, sizeof(buf)-1, NULL, 0, NULL, 0);

        printf("%-3d $%s = %s\n", i, var[i].varname, buf);
    }
}

int http_var_header_value (void * vmsg, int type, char * name, int namelen, char * buf, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;

    if (!msg) return -1;

    punit = http_header_get(msg, type, name, namelen);
    if (!punit) return -2;

    if (buf && len > 0) {
        str_secpy(buf, len, HUValue(punit), punit->valuelen);
        return strlen(buf);
    }

    return punit->valuelen;
}

int http_var_header_value_set (void * vmsg, int type, char * name, int namelen, char * buf, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;

    if (!msg) return -1;
    if (!buf) return -2;
    if (len < 0) len = strlen(buf);
    if (len < 0) return -3;

    http_header_del(msg, type, name, namelen);

    return http_header_append(msg, type, name, namelen, buf, len);
}

int http_var_cookie_value (void * vmsg, char * name, int namelen, char * buf, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    HeaderUnit * punit = NULL;
 
    if (!msg) return -1;
 
    if (name && namelen < 0) namelen = strlen(name);
    if (!name || namelen <= 0) {
        if (buf && len > 0) {
            return str_secpy(buf, len, msg->req_cookie, msg->req_cookie_len);
        }
        return msg->req_cookie_len;
    }

    punit = http_req_getcookie(msg, name, namelen);
    if (!punit) return -2;
 
    if (buf && len > 0) {
        str_secpy(buf, len, HUValue(punit), punit->valuelen);
        return strlen(buf);
    }

    return punit->valuelen;
}

int http_var_cookie_value_set (void * vmsg, char * name, int namelen, char * buf, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
 
    if (!msg) return -1;
    if (!buf) return -2;
    if (len < 0) len = strlen(buf);
    if (len < 0) return -3;
 
    http_req_delcookie(msg, name, namelen);

    return http_req_addcookie(msg, name, namelen, buf, len);
}


int http_var_query_value (void * vmsg, char * name, int namelen, char * buf, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    char       * pval = NULL;
    int          vlen = 0;
    char         tmpbuf[64];
    int          seq = 0;
    
    if (!msg) return -1;
    if (!msg->req_query_kvobj) return -2;

    if (name && namelen < 0) namelen = strlen(name);
    if (!name || namelen <= 0) {
        if (buf && len > 0) {
            return str_secpy(buf, len, msg->req_query, msg->req_querylen);
        }
        return msg->req_querylen;
    }

    if (kvpair_getP(msg->req_query_kvobj, name, namelen, 0, (void **)&pval, &vlen) <= 0) {
        for (seq = 0; seq < namelen && isdigit(name[seq]); seq++);
        if (seq < namelen) return -12;

        str_secpy(tmpbuf, sizeof(tmpbuf)-1, name, namelen);
        seq = strtol(tmpbuf, NULL, 10);

        if (kvpair_seq_get(msg->req_query_kvobj, seq, NULL, NULL, 0, (void **)&pval, &vlen) <= 0) {
            return -13;
        }
    }
 
    if (buf && len > 0) {
        str_secpy(buf, len, pval, vlen);
        return strlen(buf);
    }

    return vlen;
}

int http_var_query_value_set (void * vmsg, char * name, int namelen, char * buf, int len)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    char       * key = NULL;
    int          keylen = 0;
    char         tmpbuf[64];
    int          seq = 0;

    if (!msg) return -1;
    if (!name || namelen <= 0) return -2;
    if (!buf) return -3;
    if (len < 0) len = strlen(buf);
    if (len < 0) return -4;

    if (!msg->req_query_kvobj) return -5;

    if (kvpair_getP(msg->req_query_kvobj, name, namelen, 0, NULL, NULL) <= 0) {
        for (seq = 0; seq < namelen && isdigit(name[seq]); seq++);
        if (seq < namelen) return -12;

        str_secpy(tmpbuf, sizeof(tmpbuf)-1, name, namelen);
        seq = strtol(tmpbuf, NULL, 10);

        if (kvpair_seq_get(msg->req_query_kvobj, seq, (void **)&key, &keylen, 0, NULL, NULL) <= 0)
            return -13;

    }  else {
        key = name; keylen = namelen;
    }

    kvpair_del(msg->req_query_kvobj, key, keylen, -1);

    return kvpair_add(msg->req_query_kvobj, key, keylen, buf, len);
}


int http_var_datetime_value(void * vmsg, char * name, int namelen, char * buf, int len, int type)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    struct tm    st;
    time_t       curt;

    if (!msg) return -1;
 
    if (name && namelen == 10 && strncasecmp(name, "createtime", 10) == 0)
        curt = msg->createtime.s;
    else if (name && namelen == 5 && strncasecmp(name, "stamp", 5) == 0)
        curt = msg->stamp;
    else
        curt = time(0);
 
    if (type == 8) { //$unixtime, $unixtime[createtime], $unixtime[stamp]
        if (buf && len > 10) sprintf(buf, "%lu", curt);

        for (len = 0; curt > 0; len++) curt /= 10;
        return len;
    }

    st = *localtime(&curt);

    if (type == 6) {
        if (name && namelen == 7 && strncasecmp(name, "compact", 7) == 0) {
            if (buf && len >= 8)
                sprintf(buf, "%04d%02d%02d", st.tm_year+1900, st.tm_mon+1, st.tm_mday);
        }

        if (buf && len >= 10)
            sprintf(buf, "%04d-%02d-%02d", st.tm_year+1900, st.tm_mon+1, st.tm_mday);

        return 10;

    } else if (type == 7) {
        if (buf && len >= 8)
            sprintf(buf, "%02d:%02d:%02d", st.tm_hour, st.tm_min, st.tm_sec);

        return 8;

    } else {
        if (buf && len >= 19)
            sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
                    st.tm_year+1900, st.tm_mon+1, st.tm_mday,
                    st.tm_hour, st.tm_min, st.tm_sec);
        return 19;
    }

    return 0;
}

int http_var_fileattr_value(void * vmsg, char * name, int namelen, char * buf, int len, int type)
{
    HTTPMsg    * msg = (HTTPMsg *)vmsg;
    char         fname[2048];
    char       * lastvar = NULL;
    int          ret = 0;
    int          retlen = 0;
    int64        fsize = 0;
    time_t       mtime = 0;
    time_t       ctime = 0;

    if (!msg) return -1;

    if (!name || namelen <= 0) goto nulret;

    if (type == 9) lastvar = "filemtime";
    else if (type == 10) lastvar = "filectime";
    else if (type == 11) lastvar = "filesize";
    else goto nulret;

    ret = http_var_copy(msg, name, namelen, fname, sizeof(fname)-1, NULL, 0, lastvar, 3);
    if (ret <= 0) goto nulret;

    if (file_attr(fname, NULL, &fsize, NULL, &mtime, &ctime) < 0) goto nulret;

    if (type == 9) {
        if (buf && len >= 10) sprintf(buf, "%lu", mtime);
        for (retlen = 0; mtime > 0; retlen++) mtime /= 10;

    } else if (type == 10) {
        if (buf && len >= 10) sprintf(buf, "%lu", ctime);
        for (retlen = 0; ctime > 0; retlen++) ctime /= 10;

    } else if (type == 11) {
#if defined(_WIN32) || defined(_WIN64)
        if (buf) sprintf(buf, "%I64d", fsize);
#else
        if (buf) sprintf(buf, "%lld", fsize);
#endif
        for (retlen = 0; fsize > 0; retlen++) fsize /= 10;
    }

    return retlen;

nulret:
    sprintf(buf, "0");
    return 1;
}


void * var_obj_alloc(int alloctype, void * mpool)
{
    var_obj_t  * obj = NULL;

    obj = k_mem_zalloc(sizeof(*obj), alloctype, mpool);
    if (!obj) return NULL;

    obj->alloctype = alloctype;
    obj->mpool = mpool;

    return obj;
}

void var_obj_free (void * vobj)
{
    var_obj_t * obj = (var_obj_t *)vobj;

    if (!obj) return;

    if (obj->name) k_mem_free(obj->name, obj->alloctype, obj->mpool);
    if (obj->value) k_mem_free(obj->value, obj->alloctype, obj->mpool);

    k_mem_free(obj, obj->alloctype, obj->mpool);
}

int var_obj_cmp_name (void * a, void * b)
{
    var_obj_t * obj = (var_obj_t *)a;
    char      * name = (char *)b;

    if (!obj) return -1;
    if (!name) return 1;

    return str_casecmp(obj->name, name);
}


