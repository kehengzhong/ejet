/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_HEADER_H_
#define _HTTP_HEADER_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HeaderUnit_ {
    void       * res[2];

    char       * name;
    int          namelen;
    char       * value;
    int          valuelen;

    uint32       namepos;
    uint32       valuepos;
    frame_p      frame;

    void       * next;

} HeaderUnit;

#define HUName(unit) ((char *)frameP((unit)->frame) + (unit)->namepos)
#define HUValue(unit) ((char *)frameP((unit)->frame) + (unit)->valuepos)
#define HUPos(frame, p) ((char *)(p) - (char *)frameP(frame))


HeaderUnit * hunit_alloc     ();
int          hunit_free      (void * vhunit);
void         hunit_void_free (void * vhunit);

int     hunit_cmp_hunit_by_name(void * a, void * b);
ulong   hunit_hash_func (void * key);
int     hunit_cmp_key (void * a, void * b);

int     hunit_set_hashfunc (hashtab_t * htab);

int          hunit_add (hashtab_t * htab, char * name, int namelen, void * value);
HeaderUnit * hunit_get (hashtab_t * htab, char * name, int namelen);
HeaderUnit * hunit_del (hashtab_t * htab, char * name, int namelen);

HeaderUnit * hunit_get_from_list (arr_t * hlist, char * name, int namelen);


typedef int HeaderEncode (void * vmsg, HeaderUnit * unit);
typedef int HeaderDecode (void * vmsg, char * pbin, int binlen);


int http_header_add (void * vmsg, int type, char * name, int namelen, char * value, int valuelen);
int http_header_del (void * vmsg, int type, char * name, int namelen);
int http_header_delall    (void * vmsg, int type);
 
HeaderUnit * http_header_get       (void * vmsg, int type, char * name, int namelen);
HeaderUnit * http_header_get_index (void * vmsg, int type, int index);
 
 
int    http_header_get_int    (void * vmsg, int type, char * name, int namelen);
uint32 http_header_get_uint32 (void * vmsg, int type, char * name, int namelen);
long   http_header_get_long   (void * vmsg, int type, char * name, int namelen);
ulong  http_header_get_ulong  (void * vmsg, int type, char * name, int namelen);
int64  http_header_get_int64  (void * vmsg, int type, char * name, int namelen);
uint64 http_header_get_uint64 (void * vmsg, int type, char * name, int namelen);
 
 
int http_header_append (void * vmsg, int type, char * name, int namelen, char * value, int valuelen);
/* date string defined by RFC 822, updated by RFC 1123
   Sun, 17 Dec 2000 08:21:33 GMT   */
int http_header_append_date   (void * vmsg, int type, char * name, int namelen, time_t dtval);
int http_header_append_int    (void * vmsg, int type, char * name, int namelen, int ival);
int http_header_append_uint32 (void * vmsg, int type, char * name, int namelen, uint32 ival);
int http_header_append_long   (void * vmsg, int type, char * name, int namelen, long ival);
int http_header_append_ulong  (void * vmsg, int type, char * name, int namelen, ulong ival);
int http_header_append_int64  (void * vmsg, int type, char * name, int namelen, int64 ival);
int http_header_append_uint64 (void * vmsg, int type, char * name, int namelen, uint64 ival);
 

int http_entity_header_parse (void * vmsg, int type, char * pbyte, int len);

#ifdef __cplusplus
}
#endif

#endif

