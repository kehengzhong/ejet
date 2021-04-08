/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_FORM_H_
#define _HTTP_FORM_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HTTPForm_ {
    char      * name;        //allocated, need free
    char      * ctype;       //allocated, need free
     
    uint8       formtype;    //0-form data  1-file
 
    char      * filename;    //allocated, need free
    char      * basename;    //allocated, need free
    char      * extname;
 
    int64       valuepos;
    int64       valuelen;
 
    chunk_t   * body_chunk;
    uint8       filecache;
 
} HTTPForm, http_form_t;

void * http_form_alloc();
void   http_form_free (void * vform);

void * http_form_node (void * vmsg, char * key);

int http_form_get    (void * vmsg, char * key, char ** ctype, uint8 * formtype, char ** fname, int64 * valuelen);
int http_form_value  (void * vmsg, char * key, char * value, int64 valuelen);
int http_form_valuep (void * vmsg, char * key, int64 pos, char ** pvalue, int64 * valuelen);
int http_form_tofile (void * vmsg, char * key, int filefd);

int http_form_multipart_parse (void * vmsg, arr_t * formlist);


typedef struct FormDataNode_ {
    void    * res[2];
 
    char    * pval;      //Content-Disposition: form-data; name="TUploadFile"; filename="F:\tmp\onebyte.txt"
    int       valuelen;
 
    char    * pbody;         //file content or form-var data
    int       bodylen;
    int       bodypos;       //if filecache, gives the offset
    char      bodycont[512]; //if filecache, store the body content
 
    char      conttype[64];  // form data content type
    int       typelen;
 
    uint8     filecache;          //0-memory 1-file cache
    char      filecachename[128]; //multipart-form content file name
 
    uint8     fileflag;           //0-form data  1-file content
    char      var[128];           //variable name
    char      filename[128];
    char      basename[128];
    char      extname[32];
    char      path[128];         //httpdoc real path of the request file
} FormDataNode;

int ParseReqMultipartForm (void * vmsg, arr_t * formdatalist);

#ifdef __cplusplus
}
#endif

#endif


