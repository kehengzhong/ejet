/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_CHUNK_H_
#define _HTTP_CHUNK_H_

#include "chunk.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct http_buf {
    uint8         * pbgn;
    int             len;

    uint8         * body_bgn;
    int             body_len;

    uint8           alloc;
} HTTPBuf;

typedef struct http_chunk_item {
    int64           chksize;
    int64           chklen;

    int64           recvsize;
    int64           recvlen;

    uint8           gotall;

    arr_t         * buf_list;
    
} HTTPChunkItem;

typedef struct http_chunk {

    uint8           gotall;
    uint8           gotallbody;

    int64           chksize;  //byte num including chunk size line, chunk body, chunk header, trailer
    int64           chklen;   //actual, available content
    int64           recvsize; //byte num including chunk size line, chunk body, chunk header, trailer
    int64           recvlen;  //actual, available content
    int             chknum;

    /* if the chunk got all bytes, append it to list */
    HTTPChunkItem * curitem;

    arr_t         * item_list;

    int             enthdrsize;
    HTTPBuf       * enthdr;

    chunk_t       * chunk;

} HTTPChunk;


void * http_chunk_alloc ();
void   http_chunk_free (void * vchk);

int    http_chunk_zero (void * vchk);
void * http_chunk_dup  (void * vchk);

chunk_t * http_chunk_obj (void * vchk);

int    http_chunk_add_bufptr (void * vchk, void * pbgn, int len, int * rmlen);

int    http_chunk_gotall (void * vchk);


#ifdef __cplusplus
}
#endif

#endif


