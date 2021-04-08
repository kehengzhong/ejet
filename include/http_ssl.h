/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#ifndef _HTTP_SSL_H_
#define _HTTP_SSL_H_

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_OPENSSL

int    http_ssl_library_init    ();

void * http_ssl_server_ctx_init (char * cert, char * prikey, char * cacert);
void * http_ssl_client_ctx_init (char * cert, char * prikey, char * cacert);
int    http_ssl_ctx_free        (void * vctx);

SSL  * http_ssl_new             (SSL_CTX * ctx, void * vcon);
int    http_ssl_free            (SSL * ssl);

void * http_con_from_ssl        (SSL * ssl);

/* before SSL handshake, TCP sends 'Client Hello' with servername to web server.
   The servername will be received and indicated to callback for appropriate
   certificate and private key, called SNI mechanism in TLS spec. Multiple 
   certificates can be used for different host-name in one listen port. */

int    http_ssl_servername_select (SSL * ssl, int * ad, void * arg);

#endif


int http_ssl_accept   (void * vcon);
int http_ssl_connect  (void * vcon);

int http_con_read     (void * vcon, frame_p frm, int * num, int * err);
int http_con_writev   (void * vcon, void * piov, int iovcnt, int * num, int * err);
int http_con_sendfile (void * vcon, int filefd, int64 pos, int64 size, int * num, int * err);


#ifdef __cplusplus
}
#endif

#endif


