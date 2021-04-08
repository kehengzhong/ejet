/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_VARIABLE_H_
#define _HTTP_VARIABLE_H_

#ifdef __cplusplus
extern "C" {
#endif

#define fldsizeof(type, field) sizeof(((type *)0)->field)

#define http_var_set(var, stname, field, vtype, uns, sttype)             \
                  (var)->fieldpos = offsetof(stname, field);             \
                  (var)->fldlenpos = 0;                                  \
                  (var)->haslen = 0;                                     \
                  (var)->valtype = vtype;                                \
                  (var)->unsign = uns;                                   \
                  (var)->structtype = sttype
 
#define http_var_set2(var, stname, field, fldlen, vtype, uns, sttype)    \
                  (var)->fieldpos = offsetof(stname, field);             \
                  (var)->fldlenpos = offsetof(stname, fldlen);           \
                  (var)->haslen = 1;                                     \
                  (var)->valtype = vtype;                                \
                  (var)->unsign = uns;                                   \
                  (var)->structtype = sttype

#define http_var_set3(var, vtype, sttype)                                \
                  (var)->fieldpos = 0;                                   \
                  (var)->fldlenpos = 0;                                  \
                  (var)->haslen = 0;                                     \
                  (var)->valtype = vtype;                                \
                  (var)->unsign = 0;                                     \
                  (var)->structtype = sttype

#define http_var_set4(var, stname, field, subst, subfld, vtype, uns, sttype)    \
                  (var)->fieldpos = offsetof(stname, field);             \
                  (var)->subfldpos = offsetof(subst, subfld);            \
                  (var)->substruct= 1;                                   \
                  (var)->haslen = 0;                                     \
                  (var)->valtype = vtype;                                \
                  (var)->unsign = uns;                                   \
                  (var)->structtype = sttype

#define http_var_set5(var, stname, field, subst, subfld, subfldlen, vtype, uns, sttype)    \
                  (var)->fieldpos = offsetof(stname, field);             \
                  (var)->subfldpos = offsetof(subst, subfld);            \
                  (var)->subfldlenpos = offsetof(subst, subfldlen);      \
                  (var)->substruct= 1;                                   \
                  (var)->haslen = 1;                                     \
                  (var)->valtype = vtype;                                \
                  (var)->unsign = uns;                                   \
                  (var)->structtype = sttype
 
#define http_var_set6(var, stname, field, subfld, vtype, uns)    \
                  (var)->fieldpos = offsetof(stname, field);             \
                  (var)->subfldpos = offsetof(stname, subfld);           \
                  (var)->valtype = vtype;                                \
                  (var)->condcheck = 1;                                  \
                  (var)->unsign = uns;

#define http_var_global(var, fldname, vtype, uns, sttype)                \
                  (var)->field =  fldname;                               \
                  (var)->fldlenpos = 0;                                  \
                  (var)->haslen = 0;                                     \
                  (var)->valtype = vtype;                                \
                  (var)->unsign = uns;                                   \
                  (var)->structtype = sttype


typedef struct http_variable_s {
    char           varname[32];

    void         * field;

    size_t         fieldpos;         //relative to HTTPMsg instance
    size_t         fldlenpos;        //relative to HTTPMsg instance

    size_t         subfldpos;
    size_t         subfldlenpos;

    /* 0-char 1-short 2-int 3-int64 4-char[] 5-char * 6-frame_p 7-array 8-function 9-pointer */
    unsigned       valtype    : 4;

    unsigned       unsign     : 1;   //0-signed  1-unsigned

    unsigned       structtype : 4;   //0-HTTPMsg  1-HTTPMgmt  2-HTTPLoc  3-global variable 4-other
    unsigned       haslen     : 1;   //0-ignore fldlenpos/subfldlenpos  1-in use of fldlenpos
    unsigned       substruct  : 2;   //0-no sub struct  1-sub struct

    /* 1-request header 2-cookie 3-query 4-response header 5-datetime 6-date 7-time */
    unsigned       arraytype  : 4;

    unsigned       condcheck  : 1; //check HTTPMsg->msgtype == 1 ? first-var : second-var

} http_var_t, HTTPVar;


int http_var_init (void * vmgmt);
int http_var_free (void * vmgmt);

int http_var_value (void * vmsg, char * vname, char * buf, int len);

int http_var_copy (void * vmsg, char * vstr, int vlen, char * buf, int buflen,
                   ckstr_t * pmat, int matnum, char * lastvname, int lastvtype);

void http_var_print (void * vmsg, char * varn, int len);

int http_var_header_value (void * vmsg, int type, char * name, int namelen, char * buf, int len);
int http_var_cookie_value (void * vmsg, char * name, int namelen, char * buf, int len);
int http_var_query_value (void * vmsg, char * name, int namelen, char * buf, int len);

int http_var_datetime_value(void * vmsg, char * name, int namelen, char * buf, int len, int type);


typedef struct var_obj_s {
    char       * name;
    int          namelen;
    char       * value;
    int          valuelen;
    uint8        valtype;
} var_obj_t;

void * var_obj_alloc();
void   var_obj_free (void * vobj);

int var_obj_cmp_name (void * a, void * b);


#ifdef __cplusplus
}
#endif

#endif

