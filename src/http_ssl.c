/*
 * Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
 * All rights reserved. See MIT LICENSE for redistribution.
 */

#include "adifall.ext"
#include "epump.h"

#include "http_mgmt.h"
#include "http_msg.h"
#include "http_con.h"
#include "http_listen.h"
#include "http_cli_io.h"
#include "http_srv_io.h"
#include "http_ssl.h"

#ifdef UNIX
#include <sys/mman.h>
#endif

#ifdef HAVE_OPENSSL

int ssl_conn_index;

int http_ssl_library_init ()
{
    if (!SSL_library_init ()) {
        tolog(1, "eJet - OpenSSL library init failed\n");
        return -1;
    }

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings ();

    ssl_conn_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (ssl_conn_index == -1) {
        tolog(1, "eJet - OpenSSL: SSL_get_ex_new_index() failed\n");
        return -2;
    }

    tolog(1, "eJet - OpenSSL library init successfully.\n");

    return 0;
}

void * http_ssl_server_ctx_init (char * cert, char * prikey, char * cacert)
{
    SSL_CTX     * ctx = NULL;
    struct stat   stcert;
    struct stat   stkey;
    struct stat   stca;

    if (!cert || file_stat(cert, &stcert) < 0)
        return NULL;

    if (!prikey || file_stat(prikey, &stkey) < 0)
        return NULL;

    ctx = SSL_CTX_new(SSLv23_method());
    if (!ctx) return NULL;

    /* load certificate and private key, verify the cert with private key */
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        tolog(1, "eJet - ServerSSL: loading Certificate file %s failed\n", cert);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, prikey, SSL_FILETYPE_PEM) <= 0) {
        tolog(1, "eJet - ServerSSL: loading Private Key file %s failed\n", prikey);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        tolog(1, "eJet - ServerSSL: Certificate verify failed! Private Key %s DOES NOT "
                 "match Certificate %s\n", cert, prikey);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (cacert && file_stat(cacert, &stca) >= 0) {
        if (SSL_CTX_load_verify_locations(ctx, cacert, NULL) != 1) {
            tolog(1, "eJet - ServerSSL: load CAcert %s failed\n", cacert);
            goto retctx;
        }
 
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            tolog(1, "eJet - ServerSSL: SSL_ctx_set_default_verify_path failed\n");
            goto retctx;
        }
    }

retctx:

    if (SSL_CTX_set_tlsext_servername_callback(ctx, http_ssl_servername_select) == 0) {
        tolog(1, "eJet - SSL: select servername by TLSEXT SNI failed.\n");
    }

    tolog(1, "eJet - SSL server load Cert <%s> PriKey <%s> CACert <%s> successfully\n", cert, prikey, cacert);
    return ctx;
}

void * http_ssl_client_ctx_init (char * cert, char * prikey, char * cacert)
{
    SSL_CTX     * ctx = NULL;
    struct stat   stcert;
    struct stat   stkey;
    struct stat   stca;
    uint8         hascert = 0;
    uint8         haskey = 0;
 
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) return NULL;
 
    if (cert && file_stat(cert, &stcert) >= 0) {
        /* load certificate and private key, verify the cert with private key */
        if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
            tolog(1, "eJet - ClientSSL: loading Certificate file %s failed\n", cert);
            SSL_CTX_free(ctx);
            return NULL;
        }
        hascert = 1;
    }
 
    if (prikey && file_stat(prikey, &stkey) >= 0) {
        if (SSL_CTX_use_PrivateKey_file(ctx, prikey, SSL_FILETYPE_PEM) <= 0) {
            tolog(1, "eJet - ClientSSL: loading Private Key file %s failed\n", prikey);
            SSL_CTX_free(ctx);
            return NULL;
        }
        haskey = 1;
    }
 
    if (hascert && haskey && !SSL_CTX_check_private_key(ctx)) {
        tolog(1, "eJet - ClientSSL: Certificate verify failed! Private Key %s DOES NOT "
                 "match Certificate %s\n", cert, prikey);
        SSL_CTX_free(ctx);
        return NULL;
    }
 
    if (cacert && file_stat(cacert, &stca) >= 0) {
        if (SSL_CTX_load_verify_locations(ctx, cacert, NULL) != 1) {
            tolog(1, "eJet - ClientSSL: load CAcert %s failed\n", cacert);
            goto retctx;
        }
 
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            tolog(1, "eJet - ClientSSL: SSL_ctx_set_default_verify_path failed\n");
            goto retctx;
        }
    }
 
retctx:
    return ctx;
}
 
int http_ssl_ctx_free (void * vctx)
{
    SSL_CTX * ctx = (SSL_CTX *)vctx;

    if (!ctx) return -1;

    SSL_CTX_free(ctx);

    tolog(1, "eJet - SSL server ctx freed.\n");
    return 0;
}


SSL * http_ssl_new (SSL_CTX * ctx, void * vcon)
{
    SSL     * ssl = NULL;
    HTTPCon * pcon = (HTTPCon *)vcon;
    void    * pdev = NULL;

    if (!ctx || !pcon || !pcon->pdev) return NULL;

    ssl = SSL_new(ctx);
    if (!ssl) {
        tolog(1, "eJet - SSL: createing SSL instance failed\n");
        return NULL;
    }

    pdev = pcon->pdev;

    SSL_set_fd(ssl, iodev_fd(pdev));

    if (iodev_fdtype(pdev) == FDT_ACCEPTED) {
        SSL_set_accept_state(ssl);

    } else if (iodev_fdtype(pdev) == FDT_CONNECTED) {
        SSL_set_connect_state(ssl);
    }

    if (SSL_set_ex_data(ssl, ssl_conn_index, (void *)pcon) == 0) {
        tolog(1, "eJet - SSL: SSL_set_ex_data() failed");
    }

    return ssl;
}

int http_ssl_free (SSL * ssl)
{
    if (!ssl) return -1;

    SSL_shutdown(ssl);
    SSL_free(ssl);

    return 0;
}

void * http_con_from_ssl (SSL * ssl)
{
    if (!ssl) return NULL;

    return SSL_get_ex_data(ssl, ssl_conn_index); 
}

/* before SSL handshake, TCP sends 'Client Hello' with servername to web server.
   The servername will be received and indicated to callback for appropriate
   certificate and private key, called SNI mechanism in TLS spec. Multiple 
   certificates can be used for different host-name in one listen port. */
   
int http_ssl_servername_select (SSL * ssl, int * ad, void * arg)
{
    HTTPCon    * pcon = NULL;
    HTTPListen * hl = NULL;
    HTTPHost   * host = NULL;
    char       * servername = NULL;
    SSL_CTX    * sslctx = NULL;

    if (!ssl) return SSL_TLSEXT_ERR_NOACK;

    servername = (char *)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!servername)
        return SSL_TLSEXT_ERR_NOACK;

    pcon = SSL_get_ex_data(ssl, ssl_conn_index);
    if (!pcon)
        return SSL_TLSEXT_ERR_NOACK;

    if (!pcon->ssl_link || pcon->ssl_handshaked)
        return SSL_TLSEXT_ERR_NOACK;

    hl = (HTTPListen *)pcon->hl;
    if (!hl)
        return SSL_TLSEXT_ERR_NOACK;

    host = http_listen_host_get(hl, servername);
    if (!host)
        return SSL_TLSEXT_ERR_NOACK;

    if (host->sslctx == NULL)
        return SSL_TLSEXT_ERR_NOACK;

    sslctx = (SSL_CTX *)host->sslctx;

    SSL_set_SSL_CTX(ssl, sslctx);

    SSL_set_verify(ssl, SSL_CTX_get_verify_mode(sslctx),
                        SSL_CTX_get_verify_callback(sslctx));
 
    SSL_set_verify_depth(ssl, SSL_CTX_get_verify_depth(sslctx));
 
#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
    /* only in 0.9.8m+ */
    SSL_clear_options(ssl, SSL_get_options(ssl) & ~SSL_CTX_get_options(sslctx));
#endif
 
    SSL_set_options(ssl, SSL_CTX_get_options(sslctx));
 
#ifdef SSL_OP_NO_RENEGOTIATION
    SSL_set_options(ssl, SSL_OP_NO_RENEGOTIATION);
#endif
 
    tolog(1, "eJet - SSL select server name %s successfully\n", servername);
    return SSL_TLSEXT_ERR_OK;
}

#endif


int http_ssl_accept (void * vcon)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;

#ifdef HAVE_OPENSSL

    int          acret = 0;
    int          ret;

    if (!pcon) return -1;

    if (!pcon->ssl_link || !pcon->ssl)
        return http_cli_recv(pcon);

    if (pcon->ssl_handshaked) {
        return http_cli_recv(pcon);
    }

    time(&pcon->stamp);

    acret = SSL_accept(pcon->ssl);
    if (acret == 1) {
        pcon->ssl_handshaked = 1;
    
        if (pcon->rcv_state == HTTP_CON_SSL_HANDSHAKING)
            pcon->rcv_state = HTTP_CON_READY;

        tolog(1, "eJet - SSL accept %s:%d successfully. Using cipher: %s\n",
              pcon->srcip, pcon->srcport, SSL_get_cipher(pcon->ssl));

        return http_cli_recv(pcon);
    }

    ret = SSL_get_error(pcon->ssl, acret);
    switch (ret) {
    case SSL_ERROR_WANT_READ:
        /* waiting clifd READ event */
        return 0;

    case SSL_ERROR_WANT_WRITE:
        iodev_add_notify(pcon->pdev, RWF_WRITE);
        /* waiting clifd WRITE event */
        return 0;

    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
    default:
        tolog(1, "eJet - SSL accept %s:%d but handshake failed!\n", pcon->srcip, pcon->srcport);

        http_con_close(pcon);
        break;
    }

    return 0;

#else

    return http_cli_recv(pcon);

#endif
}


int http_ssl_connect (void * vcon)
{
    HTTPCon    * pcon = (HTTPCon *)vcon;
 
#ifdef HAVE_OPENSSL
 
    int          conret = 0;
    int          ret;
 
    if (!pcon) return -1;
 
    if (!pcon->ssl_link || !pcon->ssl)
        return http_srv_send(pcon);
 
    if (pcon->ssl_handshaked) {
        return http_srv_send(pcon);
    }
 
    time(&pcon->stamp);
 
    conret = SSL_connect(pcon->ssl);
    if (conret == 1) {
        pcon->ssl_handshaked = 1;
 
        if (pcon->snd_state == HTTP_CON_SSL_HANDSHAKING)
            pcon->snd_state = HTTP_CON_SEND_READY;
 
        tolog(1, "eJet - SSL connect %s:%d successfully! Using cipher: %s\n",
              pcon->dstip, pcon->dstport, SSL_get_cipher(pcon->ssl));
 
        return http_srv_send(pcon);
    }
 
    ret = SSL_get_error(pcon->ssl, conret);
    switch (ret) {
    case SSL_ERROR_WANT_READ:
        /* waiting srvfd READ event */
        return 0;
 
    case SSL_ERROR_WANT_WRITE:
        iodev_add_notify(pcon->pdev, RWF_WRITE);
        /* waiting srvfd WRITE event */
        return 0;
 
    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
    default:
        tolog(1, "eJet - SSL connect %s:%d but handshake failed!\n", pcon->srcip, pcon->srcport);
 
        http_con_close(pcon);
        break;
    }
 
    return 0;
 
#else
 
    return http_srv_send(pcon);
 
#endif
}


int http_con_read (void * vcon, frame_p frm, int * num, int * err)
{
    HTTPCon * pcon = (HTTPCon *)vcon;
#ifdef HAVE_OPENSSL
    uint8     buf[524288];
    int       size = sizeof(buf);
    int       ret = 0, readLen = 0;
    int       sslerr = 0;
#endif

    if (!pcon) return -1;

#ifdef HAVE_OPENSSL

    if (!pcon->ssl_link)
        return frame_tcp_nbzc_recv(pcon->rcvstream, iodev_fd(pcon->pdev), num, err);

    if (!pcon->ssl) return -2;

    for (readLen = 0; ;) {
        ret = SSL_read(pcon->ssl, buf, size);

        if (ret > 0) {
            readLen += ret;
            if (frm) frame_put_nlast(frm, buf, ret);
            continue;
        }

        sslerr = SSL_get_error(pcon->ssl, ret);

        if (num) *num = readLen;

        if (ret == 0) {
            if (sslerr == SSL_ERROR_ZERO_RETURN) {
                if (err) *err = EBADF;
                return -20;

            } else {
                if (err) *err = EBADF;
                return -30;
            }

        } else { //ret < 0
            if (sslerr == SSL_ERROR_WANT_READ) {
                if (err) *err = EAGAIN;
                break;

            } else if (sslerr == SSL_ERROR_WANT_WRITE) {
                iodev_add_notify(pcon->pdev, RWF_WRITE);
                if (err) *err = EAGAIN;
                break;

            } else if (sslerr == SSL_ERROR_SSL) {
                if (err) *err = EPROTO;

            } else if (sslerr == SSL_ERROR_SYSCALL) {
                if (err) *err = errno;
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;

            } else {
                if (err) *err = EINVAL;
            }

            return -30;
        }
    }

    if (num) *num = readLen;

    return readLen;

#else
    return frame_tcp_nbzc_recv(pcon->rcvstream, iodev_fd(pcon->pdev), num, err);
#endif
}

int http_con_writev (void * vcon, void * piov, int iovcnt, int * num, int * err)
{
    HTTPCon      * pcon = (HTTPCon *)vcon;
#ifdef HAVE_OPENSSL
    struct iovec * iov = (struct iovec *)piov;
    void         * pbyte;
    int            bytelen;
    int            wbytes;
    int            wlen = 0;
    int            i;
    int            ret = 0;
    int            sslerr = 0;
#endif

    if (num) *num = 0;
    if (err) *err = 0;

    if (!pcon) return -1;

#ifdef HAVE_OPENSSL

    if (!iov || iovcnt <= 0) return 0;

    if (!pcon->ssl_link)
        return tcp_writev(iodev_fd(pcon->pdev), piov, iovcnt, num, err);

    if (!pcon->ssl) return -2;

    for (i = 0; i < iovcnt; i++) {
        pbyte = iov[i].iov_base;
        bytelen = iov[i].iov_len;

        for (wbytes = 0; wbytes < bytelen; ) {

            ret = SSL_write(pcon->ssl, pbyte + wbytes, bytelen - wbytes);
            if (ret > 0) {
                wbytes += ret;
                wlen += ret;
                continue;
            }

            sslerr = SSL_get_error(pcon->ssl, ret);
     
            if (num) *num = wlen;
     
            if (ret == 0) {
                if (sslerr == SSL_ERROR_ZERO_RETURN) {
                    if (err) *err = EBADF;
                    return -20;
     
                } else {
                    if (err) *err = EBADF;
                    return -30;
                }
     
            } else { //ret < 0
                if (sslerr == SSL_ERROR_WANT_READ) {
                    if (err) *err = EAGAIN;
                    return wlen;
    
                } else if (sslerr == SSL_ERROR_WANT_WRITE) {
                    iodev_add_notify(pcon->pdev, RWF_WRITE);
                    if (err) *err = EAGAIN;
                    return wlen;
    
                } else if (sslerr == SSL_ERROR_SSL) {
                    if (err) *err = EPROTO;
    
                } else if (sslerr == SSL_ERROR_SYSCALL) {
                    if (err) *err = errno;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        iodev_add_notify(pcon->pdev, RWF_WRITE);
                        return wlen;
                    }
    
                } else {
                    if (err) *err = EINVAL;
                }
    
                return -30;
            }
        } //end for (wbytes = 0; wbytes < bytelen; )
    }
 
    if (num) *num = wlen;
 
    return wlen;

#else
    return tcp_writev(iodev_fd(pcon->pdev), piov, iovcnt, num, err);
#endif
}

int http_con_sendfile (void * vcon, int filefd, int64 pos, int64 size, int * num, int * err)
{
    HTTPCon      * pcon = (HTTPCon *)vcon;
#ifdef HAVE_OPENSSL
    static int     mmapsize = 8192 * 1024;
    void         * pbyte = NULL;
    void         * pmap = NULL;
    int64          maplen = 0;
#if defined(_WIN32) || defined(_WIN64)
    HANDLE         hmap;
    int64          mapoff = 0;
#endif

    size_t         onelen = 0;
    int64          wlen = 0;
    int            wbytes = 0;

    int            ret = 0;
    int            sslerr = 0;
#endif
 
    if (num) *num = 0;
    if (err) *err = 0;
 
    if (!pcon) return -1;
    if (filefd < 0) return -2;
 
#ifdef HAVE_OPENSSL
 
    if (!pcon->ssl_link)
        return tcp_sendfile(iodev_fd(pcon->pdev), filefd, pos, size, num, err);
 
    if (!pcon->ssl) return -2;

    for (wlen = 0; pos + wlen < size; ) {
        onelen = size - wlen;
        if (onelen > mmapsize) onelen = mmapsize;

#ifdef UNIX
        pbyte = file_mmap(NULL, filefd, pos + wlen, onelen, PROT_READ, MAP_PRIVATE, &pmap, &maplen, NULL);
#elif defined(_WIN32) || defined(_WIN64)
        pbyte = file_mmap(NULL, (HANDLE)filefd, pos + wlen, onelen, NULL, &hmap, &pmap, &maplen, &mapoff);
#endif
        if (!pbyte) break;

        for (wbytes = 0; wbytes < onelen; ) {
            ret = SSL_write(pcon->ssl, pbyte + wbytes, onelen - wbytes);
            if (ret > 0) {
                wbytes += ret;
                wlen += ret;
                continue;
            }

            munmap(pmap, maplen);

            if (num) *num = wlen;

            sslerr = SSL_get_error(pcon->ssl, ret);
 
            if (ret == 0) {
                if (sslerr == SSL_ERROR_ZERO_RETURN) {
                    if (err) *err = EBADF;
                    return -20;
 
                } else {
                    if (err) *err = EBADF;
                    return -30;
                }
 
            } else { //ret < 0
                if (sslerr == SSL_ERROR_WANT_READ) {
                    if (err) *err = EAGAIN;
                    return wlen;
 
                } else if (sslerr == SSL_ERROR_WANT_WRITE) {
                    iodev_add_notify(pcon->pdev, RWF_WRITE);
                    if (err) *err = EAGAIN;
                    return wlen;
 
                } else if (sslerr == SSL_ERROR_SSL) {
                    if (err) *err = EPROTO;
 
                } else if (sslerr == SSL_ERROR_SYSCALL) {
                    if (err) *err = errno;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        iodev_add_notify(pcon->pdev, RWF_WRITE);
                        return wlen;
                    }
 
                } else {
                    if (err) *err = EINVAL;
                }
 
                return -30;
            }

        } //end for (wbytes = 0; wbytes < onelen; )

        munmap(pmap, maplen);
    }

    if (num) *num = wlen;

    return wlen;

#else

    return tcp_sendfile(iodev_fd(pcon->pdev), filefd, pos, size, num, err);

#endif
}

