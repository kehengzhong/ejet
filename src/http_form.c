/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
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


void * http_form_alloc()
{
    http_form_t * form = NULL;

    form = kzalloc(sizeof(*form));

    return form;
}

void http_form_free (void * vform)
{
    http_form_t * form = (http_form_t *)vform;

    if (!form) return;

    if (form->name)
        kfree(form->name);

    if (form->ctype)
        kfree(form->ctype);

    if (form->filename)
        kfree(form->filename);

    if (form->basename)
        kfree(form->basename);

    kfree(form);
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
            return chunk_readto_file(form->body_chunk, filefd, form->valuepos, form->valuelen, 0);
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

            node->name = str_dup(pbgn, len);

        } else if (ptmp - pbgn + 1 == 8 && strncasecmp(pbgn, "filename", 8) == 0) {
            pbgn = skipOver(pval+1, poct-pval-1, " \t=\"'", 5);
            if (pbgn >= poct) continue;

            ptmp = rskipOver(poct-1, poct-pbgn, " \t=\"'", 5);
            if (ptmp < pbgn) continue;
 
            pval = rskipTo(ptmp, ptmp-pbgn+1, "\\/", 2);
            if (!pval || pval < pbgn) pval = pbgn;
            else pval++;
 
            len = ptmp - pval + 1;

            node->filename = str_dup(pval, len);
            node->formtype = 1;

            pbgn = node->filename;
            pval = pbgn + len;
            pval = rskipTo(pval-1, pval-pbgn, ".", 1);
            if (pval <= pbgn) {
                node->extname = "";
                node->basename = str_dup(pbgn, len);
            } else {
                node->extname = pval;
                node->basename = str_dup(pbgn, pval - pbgn);
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
    Content-Type: text/plain
    \r\n\r\n
    <body content>\r\n
    <boundary string>\r\n
    Content-Disposition: form-data; name="TFileDesc"
    \r\n\r\n
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
 
    pat_bmvec_t  * patvec1 = NULL;
    pat_bmvec_t  * patvec2 = NULL;
 
    if (!msg) return -1;

    if ((chk = msg->req_body_chunk) == NULL)
        return -2;
 
    if (multipart_conttype_parse(msg, &boundary, &blen) < 0)
        return -100;

    /* parse the request body that contains the form data and file content */

    patvec1 = pat_bmvec_alloc(boundary, blen, 0);
    patvec2 = pat_bmvec_alloc("\r\n\r\n", 4, 0);

    memset(&vec, 0, sizeof(vec));

    fsize = chunk_size(chk, 0);
    iter = 0;

    iter = bm_find_chunk(chk, iter, boundary, blen, patvec1, NULL);
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

        bodypos = bm_find_chunk(chk, iter, "\r\n\r\n", 4, patvec2, NULL);
        if (bodypos < 0) { ret = 0; goto err_exit;}
        bodypos += 4;
 
        endpos = bm_find_chunk(chk, bodypos, boundary, blen, patvec1, NULL);
        if (endpos < 0) { ret = -350; goto err_exit; }
        iter = endpos;
 
        endpos = chunk_rskip_to(chk, endpos-1, endpos - bodypos, "\r", 1);
        if (endpos < 0 || endpos < bodypos) { ret = -360; goto err_exit; }
        bodylen = endpos - bodypos;
 
        /* now parse the headers in this section of multipart body */
        node = http_form_alloc();
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
                node->ctype = str_dup(pvalue, valuelen);
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
    pat_bmvec_free(patvec1);
    pat_bmvec_free(patvec2);
 
    return ret;
}
 

/* the following codes are obsolated by above */
 
static int parse_form_node (FormDataNode * node, char * pvalue, int valuelen, char * path)
{
    char  * pbgn = NULL;
    char  * pend = NULL;
    char  * poct = NULL;
    char  * pval = NULL;
    char  * ptmp = NULL;
    int      len = 0;
 
    if (!node) return -1;
 
    /* Content-Disposition: form-data; name="TUploadFile"; filename="D:\tools\readme.txt" */

    pbgn = pvalue; pend = pbgn + valuelen;

    if (valuelen < 9 && strncasecmp(pbgn, "form-data", 9) != 0)
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
            memset(node->var, 0, sizeof(node->var));
            if (len > sizeof(node->var)-1) len = sizeof(node->var)-1;
            memcpy(node->var, pbgn, len);

        } else if (ptmp - pbgn + 1 == 8 && strncasecmp(pbgn, "filename", 8) == 0) {
            pbgn = skipOver(pval+1, poct-pval-1, " \t=\"'", 5);
            if (pbgn >= poct) continue;
            ptmp = rskipOver(poct-1, poct-pbgn, " \t=\"'", 5);
            if (ptmp < pbgn) continue;
 
            pval = rskipTo(ptmp, ptmp-pbgn+1, "\\/", 2);
            if (!pval || pval < pbgn) pval = pbgn;
            else pval++;
 
            memset(node->filename, 0, sizeof(node->filename));
            memset(node->basename, 0, sizeof(node->basename));
            memset(node->extname, 0, sizeof(node->extname));
            memset(node->path, 0, sizeof(node->path));
 
            len = ptmp - pval + 1;
            if (len > sizeof(node->filename)-1) len = sizeof(node->filename)-1;
            memcpy(node->filename, pval, len);
 
            node->fileflag = 1;
 
            pbgn = node->filename, pval = pbgn + str_len(node->filename);
            ptmp = rskipTo(pval-1, pval-pbgn, ".", 1);
            if (ptmp > pbgn && ptmp < pval-1 && *ptmp=='.') {
                len = ptmp-pbgn;
                if (len > sizeof(node->basename)-1) len = sizeof(node->basename)-1;
                memcpy(node->basename, pbgn, len);
 
                len = pval-ptmp;
                if (len > sizeof(node->extname)-1) len = sizeof(node->extname)-1;
                memcpy(node->extname, ptmp, len);

            } else {
                len = pval-pbgn;
                if (len > sizeof(node->basename)-1) len = sizeof(node->basename)-1;
                memcpy(node->basename, pbgn, len);
            }
 
            if (path && (len=str_len(path))>0) {
                if (len > sizeof(node->path)-1) len = sizeof(node->path)-1;
                memcpy(node->path, path, len);
            }
        }
    }
 
    return 0;
}
 
int parse_req_multipart_filecache (void * vmsg, char * boundary, int blen, char * path, arr_t * formlist)
{
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    FormDataNode * node = NULL;
    char           pname[64];
    char           pvalue[256];
 
    int64          iter = 0;
    int64          fsize = 0;
    int            ret = 0;
 
    pat_bmvec_t  * patvec1 = NULL;
    pat_bmvec_t  * patvec2 = NULL;
 
    void         * fbf = NULL;
    int64          pos = 0;
 
    int64          hdbgn = 0;
    int64          hdend = 0;
    int64          valpos = 0;
    int64          endpos = 0;
    int64          bodypos = 0;
 
    int            bodylen = 0;
    int            namelen = 0;
    int            valuelen = 0;
 
    if (!msg) return -1;
    if (!formlist) return -2;
 
    if (!msg->req_file_cache || !msg->req_multipart) return -100;
 
    fbf = fbuf_init(msg->req_file_name, 64);
    if (!fbf) return -200;
 
    patvec1 = pat_bmvec_alloc(boundary, blen, 1);
    patvec2 = pat_bmvec_alloc("\r\n\r\n", 4, 1);
 
    fsize = fbuf_size(fbf);
 
    iter = 0;
    pos = bm_find_filebuf(fbf, iter, boundary, blen, 0, patvec1, NULL);
    if (pos < 0) {
        ret = -100;
        goto err_exit;
    }
 
    while (iter < fsize) {
        iter = pos + blen;
        if (fsize - iter <= 4) { ret = 0; goto err_exit; }
 
        iter += 2;
        hdbgn = iter;
        pos = bm_find_filebuf(fbf, iter, "\r\n\r\n", 4, 0, patvec2, NULL);
        if (pos < 0) { ret = 0; goto err_exit;}
        bodypos = pos + 4;
 
        pos = bm_find_filebuf(fbf, iter, boundary, blen, 0, patvec1, NULL);
        if (pos < 0) { ret = -350; goto err_exit; }
 
        endpos = fbuf_rskip_to(fbf, pos, pos - bodypos, "\r", 1);
        if (endpos < 0 || endpos < bodypos) { ret = -360; goto err_exit; }
        bodylen = endpos - bodypos;
 
        /* now parse the headers in this section of multipart body */
        node = kzalloc(sizeof(*node));
        node->bodypos = bodypos;
        node->bodylen = bodylen;
 
        hdend = hdbgn;
        while (hdend < bodypos - 4) {
            fbuf_mmap(fbf, hdend);
 
            hdbgn = fbuf_skip_over(fbf, hdend, bodypos-2-hdbgn, " \t\r\n,;", 6);
            if (hdbgn < 0 || hdbgn >= bodypos-2) break;
 
            hdend = fbuf_skip_to(fbf, hdbgn, bodypos-2-hdbgn, "\r\n", 2);
            if (hdend < 0 || hdend >= bodypos-2) break;
 
            valpos = fbuf_skip_to(fbf, hdbgn, hdend-hdbgn, ":", 1);
            if (valpos < 0 || valpos >= hdend) continue;
 
            endpos = fbuf_rskip_over(fbf, valpos-1, valpos-hdbgn, " \t", 2);
            if (endpos < 0 || endpos < hdbgn) continue;
            namelen = endpos - hdbgn + 1;
 
            valpos = fbuf_skip_over(fbf, valpos+1, hdend-valpos-1, " \t", 2);
 
            endpos = fbuf_rskip_over(fbf, hdend-1, hdend-valpos, " \t", 2);
            if (endpos < 0 || endpos < valpos) continue;
            valuelen = endpos - valpos + 1;
 
            memset(pname, 0, sizeof(pname));
            if (namelen > sizeof(pname) - 1) namelen = sizeof(pname) -1;
            fbuf_read(fbf, hdbgn, pname, namelen);
 
            memset(pvalue, 0, sizeof(pvalue));
            if (valuelen > sizeof(pvalue) - 1) valuelen = sizeof(pvalue) -1;
            fbuf_read(fbf, valpos, pvalue, valuelen);
 
            if (namelen == 19 && strncasecmp(pname, "Content-Disposition", 19) == 0) {
                parse_form_node(node, pvalue, valuelen, path);
            } else if (namelen == 12 && strncasecmp(pname, "Content-Type", 12) == 0) {
                node->typelen = valuelen;
                if (valuelen > sizeof(node->conttype) - 1)
                    valuelen = sizeof(node->conttype) - 1;
                memcpy(node->conttype, pvalue, valuelen);
            }
        }
        node->filecache = msg->req_file_cache;
        strncpy(node->filecachename, msg->req_file_name, sizeof(node->filecachename)-1);
 
        arr_push(formlist, node);
 
        if (node->fileflag == 0) {
            if (bodylen > sizeof(node->bodycont) - 1) bodylen = sizeof(node->bodycont) -1;
            fbuf_read(fbf, node->bodypos, node->bodycont, bodylen);
        }
    }
 
err_exit:
    pat_bmvec_free(patvec1);
    pat_bmvec_free(patvec2);
 
    fbuf_free(fbf);
 
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
int ParseReqMultipartForm (void * vmsg, arr_t * formdatalist)
{
    HTTPMsg      * msg = (HTTPMsg *)vmsg;
    char         * pbgn = NULL;
    char         * poct = NULL;
    char         * pend = NULL;
    char         * pbody = NULL;
    int            bodylen = 0;
    char         * phd = NULL;
    char         * phdend = NULL;
    char         * pval = NULL;
    char         * ptmp = NULL;
    int            namelen, valuelen;
    char         * boundary;
    HeaderUnit   * punit = NULL;
    static char  * formtype = "multipart/form-data";
    int            len = 0;
    FormDataNode * node = NULL;
    char           path[128];
 
    pat_kmpvec_t * patvec1 = NULL;
    pat_kmpvec_t * patvec2 = NULL;
 
    if (!msg) return -1;
    if (!formdatalist) return -2;
 
    punit = http_header_get(msg, 0, "Content-Type", 12);
    if (!punit) return -10;
 
    GetRealPath(msg, path, sizeof(path));
 
    /* compare the mime type
       Content-Type: multipart/form-data; boundary=---------------------------7d706402a6
     */
    pbgn = HUValue(punit);  pend = pbgn + punit->valuelen;
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
    boundary = pbgn;
 
    if (msg->req_file_cache)
        return parse_req_multipart_filecache(msg, boundary, len, path, formdatalist);
 
    /* parse the request body that contains the form data and file content */
    pbgn = frameP(msg->req_body_stream);
    pend = pbgn + frameL(msg->req_body_stream);
    if (pend - pbgn < len) return -300;
 
    patvec1 = pat_kmpvec_alloc(boundary, len, 1, 0);
    patvec2 = pat_kmpvec_alloc("\r\n\r\n", 4, 1, 0);
 
    poct = kmp_find_bytes(pbgn, pend-pbgn, boundary, len, patvec1);
    if (!poct || poct >= pend) return -301;
 
    while (pbgn < pend) {
 
        pbgn = poct + len;
        if (pend - pbgn == 4 && pbgn[0]=='-' && pbgn[1]=='-' && pbgn[2]=='\r' && pbgn[3]=='\n')
            return 0;

        pbgn += 2;
        if (!pbgn || pbgn >= pend) return 0;
 
        pbody = kmp_find_bytes(pbgn, pend-pbgn, "\r\n\r\n", 4, patvec2);
        if (!pbody || pbody+4 >= pend) return 0;
        pbody += 4;
 
        /* find the body end: \r\n--<boundary string> */
        poct = kmp_find_bytes(pbody, pend-pbody, boundary, len, patvec1);
        if (!poct) return -350;
        if (poct >= pend) return -351;
        if (poct <= pbody) return -352;
 
        poct = rskipTo(poct-1, poct-pbody, "\r", 1);
        if (!poct) return -360;
        if (poct >= pend) return -361;
        if (poct <= pbody) return -362;
        bodylen = poct - pbody;
 
        /* now parse the headers in this section of multipart body */
        node = kzalloc(sizeof(*node));
        node->pbody = pbody;
        node->bodylen = bodylen;
 
        phdend = pbgn;
        while (1) {
            phd = skipOver(phdend, pbody-phdend, " \t\r\n,;", 6);
            if (!phd || phd >= pbody) break;
            phdend = skipTo(phd, pbody-phd, "\r\n", 2);
            if (!phdend || phdend <= phd) break;
 
            pval = skipTo(phd, phdend-phd, ":", 1);
            if (!pval || pval <= phd) continue;
            ptmp = rskipOver(pval-1, pval-phd, " \t", 2);
            if (!ptmp || ptmp < phd) continue;
            namelen = ptmp - phd + 1;
 
            pval = skipOver(pval+1, phdend-pval-1, " \t", 2);
            ptmp = rskipOver(phdend-1, phdend-pval, " \t", 2);
            if (!ptmp || ptmp < pval) continue;
            valuelen = ptmp - pval + 1;
 
            if (namelen == 19 && strncasecmp(phd, "Content-Disposition", 19) == 0) {
                node->pval = pval;
                node->valuelen = valuelen;
            } else if (namelen == 12 && strncasecmp(phd, "Content-Type", 12) == 0) {
                node->typelen = valuelen;
                if (valuelen > sizeof(node->conttype) - 1)
                    valuelen = sizeof(node->conttype) - 1;
                memcpy(node->conttype, pval, valuelen);
            }
        }
        parse_form_node(node, node->pval, node->valuelen, path);
        arr_push(formdatalist, node);
    }
 
    pat_kmpvec_free(patvec1);
    pat_kmpvec_free(patvec2);
 
    return 0;
}
