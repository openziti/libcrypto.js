/*
Copyright NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <emscripten.h>

X509 *readCertificate(int certPointer);

long bio_dump_callback(BIO *bio, int cmd, const char *argp, size_t len,
                       int argi, long argl, int ret, size_t *processed)
{
    BIO *out;

    out = (BIO *)BIO_get_callback_arg(bio);
    if (out == NULL)
        return ret;

    if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
        if (ret > 0 && processed != NULL) {
            printf("read from %p [%p] (%zu bytes => %zu (0x%zX))\n",
                       (void *)bio, (void *)argp, len, *processed, *processed);
            // BIO_dump(out, argp, (int)*processed);
        } else {
            printf("read from %p [%p] (%zu bytes => %d)\n",
                       (void *)bio, (void *)argp, len, ret);
        }
    } else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN)) {
        if (ret > 0 && processed != NULL) {
            printf("write to %p [%p] (%zu bytes => %zu (0x%zX))\n",
                       (void *)bio, (void *)argp, len, *processed, *processed);
            // BIO_dump(out, argp, (int)*processed);
        } else {
            printf("write to %p [%p] (%zu bytes => %d)\n",
                       (void *)bio, (void *)argp, len, ret);
        }
    }
    return ret;
}

/**
 * Create a new SSL_CTX object, which holds various configuration and data relevant to SSL/TLS or DTLS session establishment
 * 
 * @return SSL_CTX* 
 */
SSL_CTX *ssl_CTX_new()
{
    SSL_CTX *ctx;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // if (!(ctx = SSL_CTX_new(TLSv1_3_client_method()))) {
    if (!(ctx = SSL_CTX_new(TLS_client_method()))) {
        printf("Cannot create a SSL_CTX\n");
        return NULL;
    }

    /* We won't handle incomplete read/writes due to renegotiation */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /* Specify that we need to verify the server's certificate */
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* We accept only certificates signed by the CA */
    // SSL_CTX_set_verify_depth(ctx, 1);


    // Set the cipher list
    const char *cipher_list = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA";
    int rc = SSL_CTX_set_ciphersuites(ctx, cipher_list);
    printf("ssl_CTX_new, SSL_CTX_set_ciphersuites returned [%d]\n", rc);

    /* Done, return the context */
    return ctx;
}

/**
 * Add private key to SSL_CTX object
 * 
 * @param meth 
 * @return SSL_CTX* 
 */
SSL_CTX *ssl_CTX_add_private_key(SSL_CTX *ctx, EVP_PKEY *pkey)
{
    /* Load the key */
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        printf("ERROR: Cannot load private key into SSL_CTX\n");
        return NULL;
    }

    // Set the cipher list
    const char *cipher_list = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA";
    int rc = SSL_CTX_set_ciphersuites(ctx, cipher_list);
    printf("ssl_CTX_add_private_key, SSL_CTX_set_ciphersuites returned [%d]\n", rc);

    /* Done, return the context */
    return ctx;

}

/**
 * Add certificate to SSL_CTX object
 * 
 * @param meth 
 * @return SSL_CTX* 
 */
SSL_CTX *ssl_CTX_add_certificate(SSL_CTX *ctx, int certPemPointer)
{
    /* Convert Cert PEM into X509 format */
    X509 *x509 = readCertificate(certPemPointer);

    /* Load the certificate */
    if (SSL_CTX_use_certificate(ctx, x509) != 1) {
        printf("Cannot load client's certificate file\n");
        return NULL;
    }

    // Set the cipher list
    const char *cipher_list = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA";
    int rc = SSL_CTX_set_ciphersuites(ctx, cipher_list);
    printf("ssl_CTX_add_certificate, SSL_CTX_set_ciphersuites returned [%d]\n", rc);

    /* Done, return the context */
    return ctx;
}

/**
 * Add CAs to SSL_CTX object
 * 
 * @return SSL_CTX* 
 */
SSL_CTX *ssl_CTX_add_extra_chain_cert(SSL_CTX *ctx, int casPemPointer)
{
    /* Convert CAs PEM into X509 format */
    X509 *x509 = readCertificate(casPemPointer);

    /* Load the CAs */
    if (SSL_CTX_add_extra_chain_cert(ctx, x509) != 1) {
        printf("Cannot load CAs certificate file\n");
        return NULL;
    }

    /* Done, return the context */
    return ctx;
}

/**
 * Add CAs to SSL_CTX object
 * 
 * @return SSL_CTX* 
 */
SSL_CTX *ssl_CTX_add1_to_CA_list(SSL_CTX *ctx, int casPemPointer)
{
    /* Convert CAs PEM into X509 format */
    X509 *x509 = readCertificate(casPemPointer);

    /* Load the CAs */
    if (SSL_CTX_add1_to_CA_list(ctx, x509) != 1) {
        printf("Cannot load CAs certificate file\n");
        return NULL;
    }

    /* Done, return the context */
    return ctx;
}

/**
 * Verify that the certificate and the key in SSL_CTX match
 * 
 * @param meth 
 * @return SSL_CTX* 
 */
SSL_CTX *ssl_CTX_verify_certificate_and_key(SSL_CTX *ctx)
{
    /* Verify that the certificate and the key match */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        printf("Client's certificate and key don't match\n");
        return NULL;
    }

    /* Done, return the context */
    return ctx;
}

SSL *ssl_new(SSL_CTX *ctx)
{
    SSL *ssl;

    /* Get a BIO */
    if (!(ssl = SSL_new(ctx))) {
        printf("Could not get a SSL object from context\n");
        return NULL;
    }

    /*   */
    // SSL_set_mode(ctx, SSL_MODE_ASYNC|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);
    // SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);

    /* Done, return the SSL */
    return ssl;
}


BIO *bio_new_ssl_connect(SSL_CTX *ctx)
{
    BIO *sbio;

    /* Get a BIO */
    if (!(sbio = BIO_new_ssl_connect(ctx))) {
        printf("ERROR: Could not get a BIO object from context\n");
        return NULL;
    }

    // Set the BIO to non-blocking (async)
    // BIO_set_nbio(sbio, 1);
    // Set the BIO to blocking (sync)
    BIO_set_nbio(sbio, 0);

    // Add debug dump callback
    // BIO_set_callback_ex(sbio, bio_dump_callback);

    /* Done, return the BIO */
    return sbio;
}

 void apps_ssl_info_callback(SSL *s, int where, int ret)
 {
     const char *str;
     int w = where & ~SSL_ST_MASK;

     if (w & SSL_ST_CONNECT)
         str = "SSL_connect";
     else if (w & SSL_ST_ACCEPT)
         str = "SSL_accept";
     else
         str = "undefined";

     if (where & SSL_CB_LOOP) {
         printf("%s:%s\n", str, SSL_state_string_long(s));
     } else if (where & SSL_CB_ALERT) {
         str = (where & SSL_CB_READ) ? "read" : "write";
         printf("SSL3 alert %s:%s:%s\n", str,
                    SSL_alert_type_string_long(ret),
                    SSL_alert_desc_string_long(ret));
     } else if (where & SSL_CB_EXIT) {
         if (ret == 0) {
             printf("%s:failed in %s\n",
                        str, SSL_state_string_long(s));
         } else if (ret < 0) {
             printf("%s:error in %s\n",
                        str, SSL_state_string_long(s));
         }
     }
}

SSL *bio_get_ssl(BIO *sbio)
{
    SSL *ssl;

    /* Get the SSL handle from the BIO */
    BIO_get_ssl(sbio, &ssl);

    SSL_set_info_callback(ssl, (void (*))apps_ssl_info_callback);

    /*   */
    // SSL_set_mode(ctx, SSL_MODE_ASYNC|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);
    // SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);

    /* Done, return the SSL pointer */
    return ssl;
}

int bio_set_conn_hostname(BIO *sbio, int hostnamePointer)
{
    return BIO_set_conn_hostname(sbio, hostnamePointer);
}


int bio_do_connect(BIO *sbio)
{
    /* Connect to the server */
    if (BIO_do_connect(sbio) < 1) {
        printf("Could not connect to the server\n");
        SSL     *p_ssl     = NULL;
        BIO_get_ssl(sbio, &p_ssl);
        printf("p_ssl state: %s\n",SSL_state_string_long(p_ssl));
        return -1;
    }

    /* Done */
    return 0;
}


/**
 *  ziti_connected_cb
 * 
 *  Locate the connected callback for the specified fd.  If found, invoke it
 */
// EM_JS(void, ziti_connected_cb, (int fd, int rc), {

//     const wasmFD = _zitiContext._wasmFDsById.get( fd );
//     if (wasmFD === null) {
//         throw new Error('cannot find wasmFD');
//     }

//     if (wasmFD.socket._connected_cb) {
//         wasmFD.socket._connected_cb(wasmFD.socket, rc);
//     }
// });

int ssl_do_handshake(SSL *ssl)
{
    int rc = -1; // Until success, assume failure

    // printf("ssl_do_handshake() entered ssl[%p]\n", ssl);

    /* Perform SSL handshake with the server */
    if (SSL_do_handshake(ssl) != 1) {
        printf("SSL_do_handshake failed\n");
    } else {
        printf("SSL_do_handshake succeeded\n");
        rc = 1; // success
    }

    /* Done */
    printf("ssl_do_handshake() rc=%d\n", rc);

    /* Execute the callback */
    // ziti_connected_cb( SSL_get_fd(ssl), rc );

    return 1;
}

int ssl_get_verify_result(SSL *ssl)
{
    /* Verify that SSL handshake completed successfully */
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        printf("Verification of handshake failed\n");
        return -1;
    }

    return 1;
}

int tls_write(SSL *ssl, const void *buffer, int len)
{
    // printf("wasm.tls_write() entered, ssl[%d] buffer[%p] len[%d]\n", ssl,  buffer, len);
    /* Failure till we know it's a success */
    int rc = -1;

    int fd = SSL_get_fd(ssl);

    // printf("wasm.tls_write() entered for fd[%d]\n", fd);

    if ((rc = SSL_write(ssl, buffer, (int) len)) != len) {
        printf("SSL_write failed, Cannot write to the server: rc[%d] len[%d]\n", rc, len);
    } else {
        // printf("wasm.tls_write(): SSL_write returned... rc[%d] \n", rc);
    }

    return rc;
}

// static void hexdump(const void *ptr, size_t len)
// {
//     const unsigned char *p = ptr;
//     size_t i, j;

//     for (i = 0; i < len; i += j) {
// 	for (j = 0; j < 16 && i + j < len; j++)
// 	    printf("%s%02x", j? "" : " ", p[i + j]);
//     }
//     printf("\n");
// }

/**
 *  ziti_read_cb
 * 
 *  Locate the read callback for the specified fd.  If found, invoke it
 */
EM_JS(void, ziti_read_cb, (int fd, void *buffer, int read_len, void *memory), {

    const wasmFD = _zitiContext._wasmFDsById.get( fd );

    if (wasmFD === null) {
        throw new Error('cannot find wasmFD');
    }

    // If we are connected and found the callback...
    if (wasmFD.socket._connected && wasmFD.socket._read_cb) {

        // ...and some data was actually read from the stream
        if (read_len > 0) {

            // Copy the data from WASM heap into JS heap
            let someView = Module.HEAPU8.subarray(buffer, buffer+read_len);
            var result_buffer = new ArrayBuffer(read_len);
            new Uint8Array(result_buffer).set(someView);

            // Now pass the data to the callback
            wasmFD.socket._read_cb(wasmFD.socket, result_buffer);
        } else {
            // Just call the callback so it can release teh mutex
            wasmFD.socket._read_cb(wasmFD.socket, undefined);
        }
    }

});

// /**
//  *  acquireTLSReadLock
//  * 
//  *  OpenSSL handles are NOT thread-safe, so we must synchronize our access to it.
//  * 
//  */
// EM_ASYNC_JS(void, acquireTLSReadLock, (int fd), {
//     console.log("wasm.acquireTLSReadLock() --> for fd[%d]", fd);
//     const wasmFD = _zitiContext._wasmFDsById.get( fd );
//     if (wasmFD) {
//         await wasmFD.socket.acquireTLSReadLock();
//     }
//     console.log("wasm.acquireTLSReadLock() --> LOCK ACQUIRED");
// });

// /**
//  *  releaseTLSReadLock
//  * 
//  *  OpenSSL handles are NOT thread-safe, so we must synchronize our access to it.
//  * 
//  */
// EM_JS(void, releaseTLSReadLock, (int fd), {
//     console.log("wasm.releaseTLSReadLock() <-- for fd[%d]", fd);
//     const wasmFD = _zitiContext._wasmFDsById.get( fd );
//     if (wasmFD) {
//         wasmFD.socket.releaseTLSReadLock();
//     }
//     console.log("wasm.releaseTLSReadLock() <-- LOCK RELEASED");
//     return;
// });

int tls_read(SSL *ssl, void *buffer, int len)
{
    /* Failure till we know it's a success */
    int rc = -1;

    // printf("wasm.tls_read() entered for ssl[%d] buffer[%p] len[%d]\n", ssl, buffer, len);

    int fd = SSL_get_fd(ssl);

    // printf("wasm.tls_read() entered for fd[%d]\n", fd);

    if ((rc = SSL_read(ssl, buffer, (int) len)) < 0) {
        printf("wasm.tls_read() for fd[%d] len[%d] SSL_read() failed with rc=[%d], Cannot read from the tlsDataQueue\n", fd, len, rc);
    } else {
        // printf("wasm.tls_read(): SSL_read returned... data is... \n");
        // hexdump(buffer, rc);
    }

    // printf("wasm.tls_read(): exiting rc[%d]\n");

    return rc;
}


int ssl_set_fd(SSL *ssl, int socket)
{
    return SSL_set_fd(ssl, socket);
}

int ssl_connect(SSL *ssl)
{
    /* Perform SSL Handshake  */
    return SSL_connect(ssl);
}


