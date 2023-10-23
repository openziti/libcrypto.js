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
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <main.h>
#include <emscripten.h>

const char whichWASMstring[] = WHICHWASM;

const char curtGuardString1[] = "===========================";
fd_kv_t **p_fd_kv;
const char curtGuardString2[] = "---------------------------";

char *heapStringPtr = 0;

static EVP_PKEY_CTX *ctx = NULL;



/**
 * 
 */

int generate_PEM(struct keystruct convertStruct)
{

    BIO *pemBio = BIO_new(BIO_s_secmem());

    if (convertStruct.outtype == NID_X9_62_id_ecPublicKey)
    {
        if (!PEM_write_bio_PUBKEY(pemBio, convertStruct.evp_keyobject))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }
    else if (convertStruct.outtype == NID_Private)
    {
        if (!PEM_write_bio_PrivateKey(
                pemBio,
                convertStruct.evp_keyobject,
                convertStruct.password ? EVP_aes_192_cbc() : NULL,
                NULL,
                0,
                0,
                convertStruct.password ? convertStruct.password : NULL))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }

    unsigned char *privatePEM;
    BIO_read(pemBio, privatePEM, -1);
    int len = BIO_get_mem_data(pemBio, &privatePEM);
    heapStringPtr = calloc(1, len + 1);
    heapStringPtr[len] = '\0';
    BIO_read(pemBio, heapStringPtr, len);
    BIO_free(pemBio);
    return 0;
}

// int generate_HEX(struct keystruct convertStruct)
// {

//     if (!convertStruct.EVP_ONLY)
//     {
//         EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new(convertStruct.evp_keyobject, NULL);
//         EC_KEY *EXT_EC = (EC_KEY *)EVP_PKEY_get1_EC_KEY(convertStruct.evp_keyobject);
//         BN_CTX *key_ctx;
//         key_ctx = BN_CTX_new();
//         const EC_POINT *pub_key = EC_KEY_get0_public_key(EXT_EC);
//         const BIGNUM *prv_bn_key = EC_KEY_get0_private_key(EXT_EC);
//         if (convertStruct.outtype == NID_X9_62_id_ecPublicKey)
//         {
//             heapStringPtr = EC_POINT_point2hex(convertStruct.ecgroup, pub_key, convertStruct.compressed, key_ctx);
//         }
//         else if (convertStruct.outtype == NID_Private)
//         {
//             heapStringPtr = BN_bn2hex(prv_bn_key);
//         }
//         BN_CTX_free(key_ctx);
//         EVP_PKEY_CTX_free(pkctx);
//     }
//     else
//     {
//         int (*keyFunc)(const EVP_PKEY *pkey, unsigned char *priv,
//                        size_t *len);
//         size_t size;
//         if (convertStruct.outtype == NID_X9_62_id_ecPublicKey)
//         {
//             keyFunc = &EVP_PKEY_get_raw_public_key;
//         }
//         else if (convertStruct.outtype == NID_Private)
//         {
//             keyFunc = &EVP_PKEY_get_raw_private_key;
//         }

//         if (!(*keyFunc)(convertStruct.evp_keyobject, NULL, &size))
//             return throwError();
//         unsigned char *public_bytes = malloc(size);
//         if (!(*keyFunc)(convertStruct.evp_keyobject, public_bytes, &size))
//             return throwError();
//         BIGNUM *pub_bn = BN_new();
//         BN_bin2bn(public_bytes, 32, pub_bn);
//         heapStringPtr = BN_bn2hex(pub_bn);
//         free(public_bytes);
//     }
//     toLower(heapStringPtr);
//     return 0;
// }

// struct keystruct hexToEVP(char *hex_private, int NID, int outtype, int compressed, char *password)
// {
//     bool EVP_ONLY = false;
//     int EVP_TYPE = -1;
//     int error = 0;
//     switch (NID)
//     {
//     case EVP_PKEY_HMAC:
//         EVP_ONLY = true;
//         EVP_TYPE = EVP_PKEY_HMAC;
//         break;
//     case EVP_PKEY_POLY1305:
//         EVP_ONLY = true;
//         EVP_TYPE = EVP_PKEY_POLY1305;
//         break;
//     case EVP_PKEY_SIPHASH:
//         EVP_ONLY = true;
//         EVP_TYPE = EVP_PKEY_SIPHASH;
//         break;
//     case NID_X25519:
//         EVP_ONLY = true;
//         EVP_TYPE = EVP_PKEY_X25519;
//         break;
//     case NID_ED25519:
//         EVP_ONLY = true;
//         EVP_TYPE = EVP_PKEY_ED25519;
//         break;
//     case NID_X448:
//         EVP_ONLY = true;
//         EVP_TYPE = EVP_PKEY_X448;
//         break;
//     case NID_ED448:
//         EVP_ONLY = true;
//         EVP_TYPE = EVP_PKEY_ED448;
//         break;
//     }

//     EVP_PKEY *evp_keyobject = NULL;
//     EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new(evp_keyobject, NULL);
//     EC_GROUP *ecgroup = NULL;
//     EC_KEY *ec_keypair = NULL;

//     if (!EVP_ONLY)
//     {
//         ecgroup = EC_GROUP_new_by_curve_name(NID);
//         evp_keyobject = EVP_PKEY_new();
//         ec_keypair = EC_KEY_new_by_curve_name(NID);
//         EVP_PKEY_set1_EC_KEY(evp_keyobject, ec_keypair);
//         EC_KEY_set_group(ec_keypair, ecgroup);
//         EC_KEY_set_asn1_flag(ec_keypair, OPENSSL_EC_NAMED_CURVE);
//     }
//     else
//     {
//         EVP_PKEY_set_type(evp_keyobject, EVP_TYPE);
//     }

//     /* IMPORT PRIVATE KEY AS HEX STRING */
//     BIGNUM *bn_private = BN_new();
//     BN_hex2bn(&bn_private, hex_private);
//     if (!EVP_ONLY)
//     {
//         int SET_EC_PRIVATE = EC_KEY_set_private_key(ec_keypair, bn_private);
//         if (1 != SET_EC_PRIVATE)
//         {
//             ERR_print_errors_fp(stderr);
//             error = -1;
//         }
//     }
//     else
//     {
//         unsigned char *private_bytes = malloc(32);
//         int BIN_LEN = BN_bn2bin((const BIGNUM *)bn_private, private_bytes);
//         evp_keyobject = EVP_PKEY_new_raw_private_key(EVP_TYPE, NULL, private_bytes, BN_num_bytes(bn_private));
//         free(private_bytes);
//     }

//     if (!EVP_ONLY)
//     {
//         /* CREATE PUBLIC KEY BY DOING EC MULTIPLICATION*/
//         BN_CTX *mul_ctx = BN_CTX_new();
//         EC_POINT *pub_key = EC_POINT_new(ecgroup);
//         const int MUL_SUCCESS = EC_POINT_mul(ecgroup, pub_key, bn_private, NULL, NULL, mul_ctx);
//         BN_CTX_free(mul_ctx);

//         if (1 != MUL_SUCCESS)
//         {
//             ERR_print_errors_fp(stderr);
//             error = -1;
//         }

//         EC_KEY_set_public_key(ec_keypair, pub_key);
//         EVP_PKEY_set1_EC_KEY(evp_keyobject, ec_keypair);
//         EC_KEY_set_group(ec_keypair, ecgroup);
//     }
//     struct keystruct convertStruct = {evp_keyobject, NID, outtype, EVP_ONLY, ecgroup, compressed, password, error};
//     return convertStruct;
// }

// int convertKey(int NID, long keyPointer, int outtype, int outformat, int compressed, int password)
// {
//     free(heapStringPtr);
//     char *hex_private = (char *)keyPointer;

//     struct keystruct convertStruct = hexToEVP(hex_private, NID, outtype, compressed, (char *)password);

//     if (outformat == V_ASN1_BIT_STRING)
//     {

//         generate_HEX(convertStruct);
//     }
//     else if (outformat == PEM_TYPE_CLEAR || outformat == PEM_TYPE_ENCRYPTED)
//     {
//         generate_PEM(convertStruct);
//     }

//     return (int)heapStringPtr;
// }

int generateKey(int type)
{
    EVP_PKEY *pkey = NULL;

    if (NULL == ctx) {

        ctx = EVP_PKEY_CTX_new_id(type, NULL);
        if (!ctx)
            OpenSSLDie(__FILE__, __LINE__, "EVP_PKEY_CTX_new_id");

        if (EVP_PKEY_keygen_init(ctx) <= 0)
            OpenSSLDie(__FILE__, __LINE__, "EVP_PKEY_keygen_init");

        // if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0)
            // OpenSSLDie(__FILE__, __LINE__, "EVP_PKEY_CTX_set_rsa_keygen_bits");
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        OpenSSLDie(__FILE__, __LINE__, "EVP_PKEY_keygen");


    return (int)pkey;
}

int generateECKey()
{
  BIO               *outbio = NULL;
  EC_KEY            *ecKey  = NULL;
  EVP_PKEY          *pkey   = NULL;
  int               eccgrp;

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  outbio = BIO_new(BIO_s_mem());

  /* ---------------------------------------------------------- *
   * Create a EC key sructure, setting the group type from NID  *
   * ---------------------------------------------------------- */
  eccgrp = OBJ_txt2nid("secp521r1");
  ecKey = EC_KEY_new_by_curve_name( eccgrp );

  /* -------------------------------------------------------- *
   * For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag*
   * ---------------------------------------------------------*/
  EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);

  /* -------------------------------------------------------- *
   * Create the public/private EC key pair here               *
   * ---------------------------------------------------------*/
  if (! (EC_KEY_generate_key(ecKey)))
    printf("Error generating the ECC key.");

  /* -------------------------------------------------------- *
   * Converting the EC key into a PKEY structure let us       *
   * handle the key just like any other key pair.             *
   * ---------------------------------------------------------*/
  pkey=EVP_PKEY_new();
  if (!EVP_PKEY_assign_EC_KEY(pkey,ecKey))
    printf("Error assigning ECC key to EVP_PKEY structure.");

  /* -------------------------------------------------------- *
   * Now we show how to extract EC-specifics from the key     *
   * ---------------------------------------------------------*/
//   ecKey = EVP_PKEY_get1_EC_KEY(privateKey);
//   const EC_GROUP *ecgrp = EC_KEY_get0_group(ecKey);

  /* ---------------------------------------------------------- *
   * Here we print the key length, and extract the curve type.  *
   * ---------------------------------------------------------- */
//   printf("ECC Key size: %d bit\n", EVP_PKEY_bits(privateKey));
//   printf("ECC Key type: %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));


  return (int)pkey;
}

int getPrivateKeyPEM(EVP_PKEY *pkey) {

  BIO* outbio = BIO_new( BIO_s_mem() );

  if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL)) {
    printf("Error writing private key data in PEM format\n");
    BIO_free_all(outbio);
    return (int)0;
  }

  BIO_flush(outbio);

  char* private_key_text;
  long privatePemLen = BIO_get_mem_data(outbio, &private_key_text);

  char* privatePem = calloc(1, privatePemLen + 2);
  memcpy(privatePem, private_key_text, privatePemLen);

  BIO_free_all(outbio);

  return (int)privatePem;
}

int getPublicKeyPEM(EVP_PKEY *pkey) {
    
  BIO* outbio = BIO_new( BIO_s_mem() );

  if(!PEM_write_bio_PUBKEY(outbio, pkey)) {
    printf("Error writing private key data in PEM format\n");
    BIO_free_all(outbio);
    return (int)0;
  }

  BIO_flush(outbio);

  char* public_key_text;
  long publicPemLen = BIO_get_mem_data(outbio, &public_key_text);

  char* publicPem = calloc(1, publicPemLen + 2);
  memcpy(publicPem, public_key_text, publicPemLen);

  BIO_free_all(outbio);

  return (int)publicPem;
}

// void freeECKey(EVP_PKEY *pkey) {
//   EVP_PKEY_free(pkey);
// }


int cleanup()
{
    //FIPS_mode_set(0);
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    // ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    return 0;
}
int main()
{
    //FIPS_mode_set(1);
    return 0;
}



///////////////// TLSData

void fd_kv_alloc() {
  // printf("fd_kv_alloc() entered\n");
  // printf("fd_kv_alloc() curtGuardString1 is %s\n", curtGuardString1);
  // printf("fd_kv_alloc() curtGuardString2 is %s\n", curtGuardString2);
  p_fd_kv = calloc(1, sizeof(fd_kv_t));
  // printf("fd_kv_alloc() p_fd_kv is now [%p]\n", p_fd_kv);
}

TLSDataQueue *fd_kv_getItem(int fd) {
  fd_kv_t *ptr;
  // printf("fd_kv_getItem() entered fd[%d] p_fd_kv[%p]\n", fd, p_fd_kv);
  for (ptr = *p_fd_kv; ptr != NULL; ptr = ptr->next) {
    // printf("fd_kv_getItem() inside loop ptr[%p] ptr->fd[%d] ptr->next[%p]\n", ptr, ptr->fd, ptr->next);
    if (ptr->fd == fd) {
      // printf("fd_kv_getItem() returning tlsDataQueue[%p]\n", ptr->tlsDataQueue);
      return ptr->tlsDataQueue;
    }
  }
  // printf("fd_kv_getItem() returning NULL\n");
  return NULL;
}

void fd_kv_delItem(int fd) {
  fd_kv_t *ptr, *prev;
  // printf("fd_kv_delItem() entered fd[%d]\n", fd);
  for (ptr = *p_fd_kv, prev = NULL; ptr != NULL; prev = ptr, ptr = ptr->next) {
    if (ptr->fd == fd) {
      if (ptr->next != NULL) {
        if (prev == NULL) {
          *p_fd_kv = ptr->next;
          // printf("fd_kv_delItem() 1:  *p_fd_kv is now [%p]\n", *p_fd_kv);
        } else {
          prev->next = ptr->next;
        }
      } else if (prev != NULL) {
        prev->next = NULL;
      } else {
        *p_fd_kv = NULL;
        // printf("fd_kv_delItem() 2:  *p_fd_kv is now [%p]\n", *p_fd_kv);
      }
            
      free(ptr->tlsDataQueue);
      free(ptr);
            
      return;
    }
  }
}

void fd_kv_addItem(int fd, TLSDataQueue *tlsDataQueue) {
    // printf("fd_kv_addItem() entered fd[%d] TLSDataQueue[%p]\n", fd, tlsDataQueue);
    // hexdump(buf, len);
    fd_kv_delItem(fd); /* If we already have a item with this key, delete it. */
    fd_kv_t *d = calloc(1, sizeof(struct fd_kv_t_struct));
    d->fd = fd;
    d->tlsDataQueue = tlsDataQueue;
    d->next = *p_fd_kv;
    *p_fd_kv = d;
    // printf("fd_kv_addItem() 1:  *p_fd_kv is now [%p]\n", *p_fd_kv);
}


TLSDataQueue *constructTLSDataQueue(int fd, int limit) {
  // printf("constructTLSDataQueue() entered: fd[%d] limit[%d]\n", fd, limit);

  TLSDataQueue *queue = (TLSDataQueue*) calloc(1, sizeof (TLSDataQueue));
  if (queue == NULL) {
      return NULL;
  }
  if (limit <= 0) {
      limit = 65535;
  }
  queue->fd = fd;
  queue->limit = limit;
  queue->size = 0;
  queue->head = NULL;
  queue->tail = NULL;

  return queue;
}

void destructTLSDataQueue(TLSDataQueue *queue) {
    TLSDataNODE *pN;
    while (!isEmptyTLSData(queue)) {
        pN = dequeueTLSData(queue);
        free(pN);
    }
    free(queue);
}

// static void hexdump(const void *ptr, size_t len)
// {
//     const unsigned char *p = ptr;
//     size_t i, j;

//     for (i = 0; i < len; i += j) {
// 	    for (j = 0; j < 16 && i + j < len; j++)
// 	      printf("%s%02x", j? "" : " ", p[i + j]);
//     }
//     printf("\n");
// }

char* allocateTLSDataBuf(int len) {
  char* buf = calloc( 1, len );
  // printf("allocateTLSDataBuf() returning buf[%p] len[%d]\n", buf, len);
  return buf;
}
void freeTLSDataBuf(char* buf) {
  free( buf );
}

int enqueueTLSData(TLSDataQueue *pQueue, void *buf, int len) {
  // printf("enqueueTLSData() entered: pQueue[%p] fd[%d] buf[%p] len[%d]\n", pQueue, pQueue->fd, buf, len);
  // printf("enqueueTLSData() entered, fd[%d] pQueue->size[%d]\n", pQueue->fd, pQueue->size);

  // Bad parameter
  if (pQueue == NULL) {
      return FALSE;
  }
  if (pQueue->size >= pQueue->limit) {
      return FALSE;
  }
  // hexdump(buf, len);

  // Before enqueueing a new item, purge any items currently on the queue that have been completely consumed
  bool done = false;
  TLSDataNODE *item = pQueue->head;
  TLSDataNODE *itemToPurge;
  do {
    // printf("enqueueTLSData() purge loop: item[%p]\n", item);

    if (NULL == item) {
      done = true;
    } else if ((item->data.offset < item->data.len) || (item->data.len == 0)) {
      done = true;
    } else {
      // printf("enqueueTLSData() need to purge consumed item: item[%p] fd[%d] buf[%p] offset[%d] len[%d]\n", item, pQueue->fd, item->data.buf, item->data.offset, item->data.len);
      item = item->prev;
      itemToPurge = dequeueTLSData(pQueue);
      // printf("enqueueTLSData() freeing buf[%p]\n", itemToPurge->data.buf);
      free(itemToPurge->data.buf);
      // printf("enqueueTLSData() freeing item[%p]\n", itemToPurge);
      free(itemToPurge);
      if (NULL == item) {
        done = true;
      }
    }
  }
  while (!done);


  // Allocate a node to track the encrypted data
  TLSDataNODE *pN = (TLSDataNODE*) calloc(1, sizeof (TLSDataNODE));
  // printf("enqueueTLSData() allocated new item[%p]\n", pN);
  pN->data.buf = buf;
  pN->data.len = len;
  pN->data.offset = 0;
  pN->prev = NULL;

  // if the queue is empty
  if (pQueue->size == 0) {
      pQueue->head = pN;
      pQueue->tail = pN;
    // printf("enqueueTLSData() added item to empty queue\n");
  } else {
      // add item to the end of the queue
      pQueue->tail->prev = pN;
      pQueue->tail = pN;
    // printf("enqueueTLSData() added item to end of queue\n");
  }

  pQueue->size++;
  // printf("enqueueTLSData() exiting, fd[%d] pQueue->size[%d]\n", pQueue->fd, pQueue->size);
  return TRUE;
}

TLSDataNODE * dequeueTLSData(TLSDataQueue *pQueue) {
  // printf("dequeueTLSData() entered pQueue[%p] fd[%d]\n", pQueue, pQueue->fd);

  // the queue is empty or bad param
  TLSDataNODE *item;
  if (isEmptyTLSData(pQueue))
      return NULL;
  item = pQueue->head;
  pQueue->head = (pQueue->head)->prev;
  pQueue->size--;
  // printf("dequeueTLSData() exiting, pQueue->size %d] item[%p]\n", pQueue->size, item);
  return item;
}

TLSDataNODE * peekTLSData(TLSDataQueue *pQueue) {
  // printf("peekTLSData() entered pQueue[%p] fd[%d] pQueue->size[%d]\n", pQueue, pQueue->fd, pQueue->size);
  TLSDataNODE *item;
  if (isEmptyTLSData(pQueue)) {
    // printf("peekTLSData() isEmptyTLSData says true\n");
      return NULL;
  }

  bool done = false;
  item = pQueue->head;
  do {
    // If this node has NOT been completely consumed, return it
    if (item->data.offset < item->data.len) {
      done = true;
    } else {
      // printf("peekTLSData() bypassing consumed item pQueue[%p] fd[%d] offset[%d] len[%d]\n", pQueue, pQueue->fd, item->data.offset, item->data.len);

      // Ignore consumed items, and skip to the next item in the queue
      item = item->prev;
      if (NULL == item) {
        done = true;
      }
    }
  }
  while (!done);

  // if (NULL != item) {
  //   printf("peekTLSData() exiting, pQueue->size[%d] item[%p] item.len[%d] item.offset[%d]\n", pQueue->size, item, item->data.len, item->data.offset);
  // } else {
  //   printf("peekTLSData() exiting, pQueue->size[%d] item[%p] \n", pQueue->size, item);
  // }
  return item;
}

int isEmptyTLSData(TLSDataQueue* pQueue) {
  // printf("isEmptyTLSData() entered pQueue[%p] fd[%d] pQueue->size[%d]\n", pQueue, pQueue->fd, pQueue->size);

  int ret = FALSE;

  if (pQueue == NULL) {
      //nop
  }
  if (pQueue->size == 0) {
      ret = TRUE;
  } else {
      //nop
  }
  // printf("isEmptyTLSData() exiting [%d]\n", ret);
  return ret;
}
