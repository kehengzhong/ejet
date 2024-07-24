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
 
#include "http_msg.h"
#include "http_mgmt.h"
#include "http_header.h"
#include "http_cgi.h"
#include "http_form.h"

 
int multipart_conttype_parse (void * vmsg, char ** pboundary, int * plen)
{
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    char         * pbgn = NULL;
    char         * poct = NULL;
    char         * pend = NULL;
    HeaderUnit   * punit = NULL;
    static char  * formtype = "multipart/form-data";
    int            len = 0;

    if (!msg) return -1;

    punit = http_header_get(msg, 0, "Content-Type", 12);
    if (!punit) return -10;

    /* compare the mime type
       Content-Type: multipart/form-data; boundary=---------------------------7d706402a6
     */
    pbgn = HUValue(punit);
    pend = pbgn + punit->valuelen;

    pbgn = skipOver(pbgn, pend-pbgn, " \t", 2);
    if (!pbgn || pbgn >= pend) return -100;
 
    len = str_len(formtype);
    if (pend - pbgn < len) return -101;
    if (strncasecmp(pbgn, formtype, len) != 0)
        return -200;
 
    /* parse the boundary string, pbgn skips to the begining of key 'boundary' */
    pbgn += len;
    pbgn = skipOver(pbgn, pend-pbgn, ";, \t", 4);
    if (!pbgn || pbgn >= pend) return -201;
 
    poct = skipTo(pbgn, pend-pbgn, "=", 1);
    if (!poct || poct >= pend) return -204;
 
    /* pbgn skips to the begining of value of boundary */
    pbgn = skipOver(poct + 1, pend - poct - 1, " \t", 2);
    if (!pbgn || pbgn >= pend) return -205;
 
    poct = skipTo(pbgn, pend-pbgn, " \t,;\r\n", 6);
    if (!poct) return -202;
    if (poct <= pbgn) return -203;
 
    len = poct - pbgn;

    if (pboundary) *pboundary = pbgn;
    if (plen) *plen = len;

    return 1;
}


void * http_form_alloc(int alloctype, void * mpool)
{
    http_form_t * form = NULL;

    form = k_mem_zalloc(sizeof(*form), alloctype, mpool);
    if (form) {
        form->alloctype = alloctype;
	form->mpool = mpool;
    }

    return form;
}

void http_form_free (void * vform)
{
    http_form_t * form = (http_form_t *)vform;

    if (!form) return;

    if (form->name)
        k_mem_free(form->name, form->alloctype, form->mpool);

    if (form->ctype)
        k_mem_free(form->ctype, form->alloctype, form->mpool);

    if (form->filename)
        k_mem_free(form->filename, form->alloctype, form->mpool);

    if (form->basename)
        k_mem_free(form->basename, form->alloctype, form->mpool);

    if (form->extname)
        k_mem_free(form->extname, form->alloctype, form->mpool);

    k_mem_free(form, form->alloctype, form->mpool);
}

void * http_form_node (void * vmsg, char * key)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    http_form_t * form = NULL;
    int           i, num;
 
    if (!msg || !key) return NULL;
 
    num = arr_num(msg->req_formlist);
    for (i = 0; i < num; i++) {
        form = arr_value(msg->req_formlist, i);
        if (!form) continue;
 
        if (form->name && strcasecmp(key, form->name) == 0) {
            return form;
        }
    }
 
    return NULL;
}

int http_form_get (void * vmsg, char * key, char ** ctype, uint8 * formtype, char ** fname, int64 * valuelen)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    http_form_t * form = NULL;
    int           i, num;

    if (!msg) return -1;
    if (!key) return -2;

    num = arr_num(msg->req_formlist);
    for (i = 0; i < num; i++) {
        form = arr_value(msg->req_formlist, i);
        if (!form) continue;

        if (form->name && strcasecmp(key, form->name) == 0) {
            if (ctype) *ctype = form->ctype;
            if (formtype) *formtype = form->formtype;
            if (fname) *fname = form->filename;
            if (valuelen) *valuelen = form->valuelen;
            return 1;
        }
    }

    return -100;
}

int http_form_value (void * vmsg, char * key, char * value, int64 valuelen)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    http_form_t * form = NULL;
    int           i, num;
 
    if (!msg) return -1;
    if (!key) return -2;
 
    num = arr_num(msg->req_formlist);
    for (i = 0; i < num; i++) {
        form = arr_value(msg->req_formlist, i);
        if (!form) continue;
 
        if (form->name && strcasecmp(key, form->name) == 0) {
            return chunk_read(form->body_chunk, value, form->valuepos, valuelen, 0);
        }
    }
 
    return -100;
}

int http_form_valuep (void * vmsg, char * key, int64 pos, char ** pvalue, int64 * valuelen)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    http_form_t * form = NULL;
    int           i, num;
 
    if (!msg) return -1;
    if (!key) return -2;
 
    num = arr_num(msg->req_formlist);
    for (i = 0; i < num; i++) {
        form = arr_value(msg->req_formlist, i);
        if (!form) continue;
 
        if (form->name && strcasecmp(key, form->name) == 0) {
            if (pos < 0 || pos >= form->valuelen)
                return -16;

            return chunk_read_ptr(form->body_chunk, form->valuepos + pos,
                                  form->valuelen - pos, (void **)pvalue, valuelen, 0);
        }
    }
 
    return -100;
}

int http_form_tofile (void * vmsg, char * key, int filefd)
{
    HTTPMsg     * msg = (HTTPMsg *)vmsg;
    http_form_t * form = NULL;
    int           i, num;
 
    if (!msg) return -1;
    if (!key) return -2;
 
    num = arr_num(msg->req_formlist);
    for (i = 0; i < num; i++) {
        form = arr_value(msg->req_formlist, i);
        if (!form) continue;
 
        if (form->name && strcasecmp(key, form->name) == 0) {
            return chunk_write_file(form->body_chunk, filefd, form->valuepos, form->valuelen, 0);
        }
    }
 
    return -100;
}

int http_form_data_parse (void * vnode, char * cdisp, int displen)
{
    http_form_t * node = (http_form_t *)vnode;

    char  * pbgn = NULL;
    char  * pend = NULL;
    char  * poct = NULL;
    char  * pval = NULL;
    char  * ptmp = NULL;
    int     len = 0;
 
    if (!node) return -1;
 
    /* Content-Disposition: form-data; name="TUploadFile"; filename="D:\tools\readme.txt" */
 
    pbgn = cdisp; pend = pbgn + displen;
 
    if (displen < 9 && strncasecmp(pbgn, "form-data", 9) != 0)
        return -100;
 
    pbgn += 9;
 
    for (poct = pbgn; poct < pend; ) {
        pbgn = skipOver(poct, pend-poct, " \t,;", 4);
        if (pbgn >= pend) break;
 
        poct = skipQuoteTo(pbgn, pend-pbgn, ";, \t", 4);
        if (!poct) return -100;
 
        pval = skipQuoteTo(pbgn, poct-pbgn, "=", 1);
        if (!pval || pval >= poct) continue;
 
        ptmp = rskipOver(pval-1, pval-pbgn, " \t", 2);
        if (ptmp < pbgn) continue;
 
        if (ptmp - pbgn + 1 == 4 && strncasecmp(pbgn, "name", 4) == 0) {
            pbgn = skipOver(pval+1, poct-pval-1, " \t=\"'", 5);
            if (pbgn >= poct) continue;
 
            ptmp = rskipOver(poct-1, poct-pbgn, " \t=\"'", 5);
            if (ptmp < pbgn) continue;
 
            len = ptmp - pbgn + 1;

            node->name = k_mem_str_dup(pbgn, len, node->alloctype, node->mpool);

        } else if (ptmp - pbgn + 1 == 8 && strncasecmp(pbgn, "filename", 8) == 0) {
            pbgn = skipOver(pval+1, poct-pval-1, " \t=\"'", 5);
            if (pbgn >= poct) continue;

            ptmp = rskipOver(poct-1, poct-pbgn, " \t=\"'", 5);
            if (ptmp < pbgn) continue;
 
            pval = rskipTo(ptmp, ptmp-pbgn+1, "\\/", 2);
            if (!pval || pval < pbgn) pval = pbgn;
            else pval++;
 
            len = ptmp - pval + 1;

            node->filename = k_mem_str_dup(pval, len, node->alloctype, node->mpool);
            node->formtype = 1;

            pbgn = node->filename;
            pval = pbgn + len;
            pval = rskipTo(pval-1, pval-pbgn, ".", 1);
            if (pval <= pbgn) {
                node->extname = "";
                node->basename = k_mem_str_dup(pbgn, len, node->alloctype, node->mpool);
            } else {
                node->extname = pval;
                node->basename = k_mem_str_dup(pbgn, pval - pbgn, node->alloctype, node->mpool);
            }
        }
    }
 
    return 0;
}

/* multipart format is usually used as uploading multi-format contents by POST. 
  its content-type is:
       Content-Type: multipart/form-data; boundary=---------------------------7d706402a6

  request body is as following:

    <boundary string>\r\n
    Content-Disposition: form-data; name="TUploadFile"; filename="D:\tools\readme.txt"
    Content-Type: text/plain \r\n\r\n
    <body content>\r\n
    <boundary string>\r\n
    Content-Disposition: form-data; name="TFileDesc" \r\n\r\n
    <form data>\r\n
    <boundary string>--\r\n
 */
int http_form_multipart_parse (void * vmsg, arr_t * formlist)
{
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    chunk_t      * chk = NULL;
    ckpos_vec_t    vec;

    int64          iter = 0;
    int64          fsize = 0;
    int            ret = 0;

    int64          hdbgn = 0;
    int64          hdend = 0;
    int64          valpos = 0;
    int64          endpos = 0;
    int64          bodypos = 0;
 
    int            bodylen = 0;
    int            namelen, valuelen;

    char           pname[128];
    char           pvalue[256];

    char         * boundary;
    int            blen = 0;
    http_form_t  * node = NULL;
 
    pat_sunvec_t   patvec1 = {0};
    pat_sunvec_t   patvec2 = {0};
 
    if (!msg) return -1;

    if ((chk = msg->req_body_chunk) == NULL)
        return -2;
 
    if (multipart_conttype_parse(msg, &boundary, &blen) < 0)
        return -100;

    /* parse the request body that contains the form data and file content */

    pat_sunvec_init(&patvec1, boundary, blen, 0, 0);
    pat_sunvec_init(&patvec2, "\r\n\r\n", 4, 0, 0);

    memset(&vec, 0, sizeof(vec));

    fsize = chunk_size(chk, 0);
    iter = 0;

    iter = chunk_sun_find_bytes(chk, iter, boundary, blen, &patvec1, NULL);
    if (iter < 0) {
        ret = -100;
        goto err_exit;
    }
 
    while (iter < fsize) {
        iter = iter + blen;

        if (fsize - iter == 4 && 
            chunk_char(chk, iter + 0, &vec, NULL) == '-' &&
            chunk_char(chk, iter + 1, &vec, NULL) == '-' &&
            chunk_char(chk, iter + 2, &vec, NULL) == '\r' &&
            chunk_char(chk, iter + 3, &vec, NULL) == '\n')
        { ret = 0; goto err_exit; }
 
        iter += 2;
        if (iter >= fsize) goto err_exit;
        hdend = iter;

        bodypos = chunk_sun_find_bytes(chk, iter, "\r\n\r\n", 4, &patvec2, NULL);
        if (bodypos < 0) { ret = 0; goto err_exit;}
        bodypos += 4;
 
        endpos = chunk_sun_find_bytes(chk, bodypos, boundary, blen, &patvec1, NULL);
        if (endpos < 0) { ret = -350; goto err_exit; }
        iter = endpos;
 
        endpos = chunk_rskip_to(chk, endpos-1, endpos - bodypos, "\r", 1);
        if (endpos < 0 || endpos < bodypos) { ret = -360; goto err_exit; }
        bodylen = endpos - bodypos;
 
        /* now parse the headers in this section of multipart body */
        node = http_form_alloc(msg->alloctype, msg->kmemblk);
        node->valuepos = bodypos;
        node->valuelen = bodylen;
 
        while (hdend < bodypos - 4) {
            hdbgn = chunk_skip_over(chk, hdend, bodypos-2-hdend, " \t\r\n,;", 6);
            if (hdbgn < 0 || hdbgn >= bodypos-2) break;
 
            hdend = chunk_skip_to(chk, hdbgn, bodypos-2-hdbgn, "\r\n", 2);
            if (hdend < 0 || hdend >= bodypos-2) break;
 
            valpos = chunk_skip_to(chk, hdbgn, hdend-hdbgn, ":", 1);
            if (valpos < 0 || valpos >= hdend) continue;
 
            endpos = chunk_rskip_over(chk, valpos-1, valpos-hdbgn, " \t", 2);
            if (endpos < 0 || endpos < hdbgn) continue;
            namelen = endpos - hdbgn + 1;
 
            valpos = chunk_skip_over(chk, valpos+1, hdend-valpos-1, " \t", 2);
 
            endpos = chunk_rskip_over(chk, hdend-1, hdend-valpos, " \t", 2);
            if (endpos < 0 || endpos < valpos) continue;
            valuelen = endpos - valpos + 1;
 
            memset(pname, 0, sizeof(pname));
            if (namelen > sizeof(pname) - 1) namelen = sizeof(pname) -1;
            chunk_read(chk, pname, hdbgn, namelen, 0);
 
            memset(pvalue, 0, sizeof(pvalue));
            if (valuelen > sizeof(pvalue) - 1) valuelen = sizeof(pvalue) -1;
            chunk_read(chk, pvalue, valpos, valuelen, 0);
 
            if (namelen == 19 && strncasecmp(pname, "Content-Disposition", 19) == 0) {
                http_form_data_parse(node, pvalue, valuelen);

            } else if (namelen == 12 && strncasecmp(pname, "Content-Type", 12) == 0) {
                node->ctype = k_mem_str_dup(pvalue, valuelen, msg->alloctype, msg->kmemblk);
            }
        }

        node->body_chunk = chk;
        node->filecache = msg->req_file_cache;
 
        if (formlist)
            arr_push(formlist, node);
        else
            arr_push(msg->req_formlist, node);
    }
 
err_exit:
    return ret;
}
 

/* When upload file by POST method, Post Body format as follows
 
<boundary string>\r\n
Content-Disposition: form-data; name="TUploadFile"; filename="D:\tools\readme.txt"
Content-Type: text/plain
\r\n\r\n
<body content>\r\n
<boundary string>\r\n
Content-Disposition: form-data; name="TFileDesc"
\r\n\r\n
<form data>\r\n
<boundary string>--\r\n
 
 
actual data package as follows:
-----------------------------7d7127950780
Content-Disposition: form-data; name="TUploadFile"; filename="F:\tmp\onebyte.txt"
Content-Type: text/plain
 
a
-----------------------------7d7127950780
Content-Disposition: form-data; name="TFileDesc"
 
hi
-----------------------------7d7127950780--\r\n
 
Boundary string contained in Header as follows:
 
Content-Type: multipart/form-data; boundary=---------------------------7d706402a6
 
 */
