OUT_DIR=./dist
MODULES_DIR=$(OUT_DIR)/modules
OPENSSL_DIR=./openssl
EMMAKE ?= emmake
EMCC ?= emcc
EMCONFIGURE ?= emconfigure
EMCONFIGURE_JS ?= 0
# OPENSSL_EMCC_CFLAGS := -g -O2 -fPIC -DNDEBUG -D__STDC_NO_ATOMICS__=1 -DCRYPTO_TDEBUG=1 -fsanitize=address
# OPENSSL_EMCC_CFLAGS := -g -O2 -fPIC -DNDEBUG -D__STDC_NO_ATOMICS__=1 -DCRYPTO_TDEBUG=1
OPENSSL_EMCC_CFLAGS := -O2 -fPIC -DNDEBUG -D__STDC_NO_ATOMICS__=1

NODE := $(shell if which nodejs >/dev/null 2>&1 ; then echo nodejs; else echo node ; fi)

GIT_TAG := $(shell git rev-parse --short HEAD)
@echo  Git tag is: $(GIT_TAG)

#
#
#
EXPORTED_FUNCTIONS = [\
_fd_kv_alloc,\
_fd_kv_getItem,\
_fd_kv_delItem,\
_fd_kv_addItem,\
_constructTLSDataQueue,\
_destructTLSDataQueue,\
_allocateTLSDataBuf,\
_freeTLSDataBuf,\
_enqueueTLSData,\
_dequeueTLSData,\
_peekTLSData,\
_isEmptyTLSData,\
_malloc,\
_OPENSSL_init,\
_EVP_PKEY_new,\
_EVP_PKEY_paramgen_init,\
_EVP_PKEY_CTX_set_rsa_keygen_bits,\
_EVP_PKEY_paramgen,\
_EVP_PKEY_CTX_new_id,\
_EVP_PKEY_keygen_init,\
_EVP_PKEY_keygen,\
_EVP_PKEY_free,\
_EVP_PKEY_CTX_free,\
_EVP_PKEY_get1_DSA,\
_BIO_new_fp,\
_PEM_write_bio_DSAPrivateKey,\
_DSA_free,\
_EVP_PKEY_free,\
_RSA_new,\
_EVP_PKEY_keygen,\
_createCertificateSigningRequest,\
_cleanup,\
_createBuffer,\
_destroyBuffer,\
_generateKey,\
_generateECKey,\
_getPrivateKeyPEM,\
_getPublicKeyPEM,\
_ssl_CTX_new,\
_ssl_CTX_add_private_key,\
_ssl_CTX_add_certificate,\
_ssl_CTX_add_extra_chain_cert,\
_ssl_CTX_verify_certificate_and_key,\
_ssl_CTX_add_extra_chain_cert,\
_ssl_CTX_add1_to_CA_list,\
_bio_new_ssl_connect,\
_bio_get_ssl,\
_bio_set_conn_hostname,\
_bio_do_connect,\
_ssl_do_handshake,\
_SSL_is_init_finished,\
_SSL_get_fd,\
_ssl_get_verify_result,\
_ssl_new,\
_ssl_set_fd,\
_ssl_connect,\
_tls_write,\
_whichWASMstring,\
_tls_read\
]

EXPORTED_RUNTIME_FUNCTIONS="[\
  'setValue',\
  'getValue',\
  'ccall',\
  'cwrap',\
  'stringToUTF8',\
  'lengthBytesUTF8',\
  'addFunction'\
]"

export EMCONFIGURE_JS

.PHONY: clean release libcrypto


#####################
# OpenSSL libcrypto #
#####################
libcrypto: libcrypto.JSPI.js libcrypto.NO-JSPI.js

libcrypto.JSPI.js: libcrypto.JSPI.wasm
	@echo +++ libcrypto.JSPI.js step

libcrypto.NO-JSPI.js: libcrypto.NO-JSPI.wasm
	@echo +++ libcrypto.NO-JSPI.js step

libcrypto.JSPI.wasm: $(OPENSSL_DIR)/libcrypto.a $(OPENSSL_DIR)/libssl.a
	@echo +++ libcrypto.JSPI.$(GIT_TAG).wasm step
	EMCC_CFLAGS="$(OPENSSL_EMCC_CFLAGS)" $(EMCC) -DWHICHWASM='"JSPI"' src/c/*.c \
		$(OPENSSL_DIR)/libcrypto.a $(OPENSSL_DIR)/libssl.a -Iopenssl/include -Iopenssl/include/openssl -Isrc/c/include \
		-o lib/libcrypto.JSPI.$(GIT_TAG).js \
		--pre-js src/asyncifyStubs.js \
		--js-library src/js-library.js \
		--no-entry \
		-s EXPORTED_FUNCTIONS="$(EXPORTED_FUNCTIONS)" \
		-s EXPORTED_RUNTIME_METHODS=$(EXPORTED_RUNTIME_FUNCTIONS) \
		-s ASYNCIFY_EXPORTS=ssl_do_handshake,tls_read \
		-s DETERMINISTIC \
		-s FILESYSTEM=0 \
		-s ERROR_ON_UNDEFINED_SYMBOLS=0 \
    	-s ALLOW_MEMORY_GROWTH=1 \
		-s USE_ES6_IMPORT_META=0 \
		-s SINGLE_FILE=0 \
		-s EXPORT_ES6=1 \
		-s INVOKE_RUN=0 \
		-s EXPORT_NAME=libCrypto \
		-s ENVIRONMENT=web \
		-s MODULARIZE=1 \
		-s STANDALONE_WASM \
		-s WASM_BIGINT \
    	-s JSPI \
    	-s PROXY_POSIX_SOCKETS=0 \
		-s WASM=1

#   -fsanitize=address \

#   -s ASYNCIFY_IMPORTS=[start_ziti_awaitTLSDataQueue_timer] \

# 	-s ASSERTIONS=1 \
#		-s VERBOSE \
#   -s MEMORY64=2 \
#		-s SAFE_HEAP=1 \
#		-s SAFE_HEAP_LOG=1 \


libcrypto.NO-JSPI.wasm: $(OPENSSL_DIR)/libcrypto.a $(OPENSSL_DIR)/libssl.a
	@echo +++ libcrypto.NO-JSPI.$(GIT_TAG).wasm step
	EMCC_CFLAGS="$(OPENSSL_EMCC_CFLAGS)" $(EMCC) -DWHICHWASM='"NO-JSPI"' src/c/*.c  \
		$(OPENSSL_DIR)/libcrypto.a $(OPENSSL_DIR)/libssl.a -Iopenssl/include -Iopenssl/include/openssl -Isrc/c/include \
		-o lib/libcrypto.NO-JSPI.$(GIT_TAG).js \
		--pre-js src/asyncifyStubs.js \
		--js-library src/js-library.js \
		--no-entry \
		-s EXPORTED_FUNCTIONS="$(EXPORTED_FUNCTIONS)" \
		-s EXPORTED_RUNTIME_METHODS=$(EXPORTED_RUNTIME_FUNCTIONS) \
		-s ASYNCIFY_EXPORTS=ssl_do_handshake,tls_read \
		-s DETERMINISTIC \
		-s FILESYSTEM=0 \
		-s ERROR_ON_UNDEFINED_SYMBOLS=0 \
		-s STRICT=1 \
    	-s ALLOW_MEMORY_GROWTH=1 \
		-s USE_ES6_IMPORT_META=0 \
		-s SINGLE_FILE=0 \
		-s EXPORT_ES6=1 \
		-s INVOKE_RUN=0 \
		-s EXPORT_NAME=libCrypto \
		-s ENVIRONMENT=web \
		-s MODULARIZE=1 \
		-s STANDALONE_WASM \
		-s WASM_BIGINT \
    	-s ASYNCIFY=1 \
    	-s PROXY_POSIX_SOCKETS=0 \
		-s WASM=1


$(OPENSSL_DIR)/libcrypto.a: $(OPENSSL_DIR)/configdata.pm
	@echo +++ libcrypto.a step
	cd $(OPENSSL_DIR) && EMCC_CFLAGS="$(OPENSSL_EMCC_CFLAGS)" $(EMMAKE) make libcrypto.a CFLAGS="$(OPENSSL_EMCC_CFLAGS)"

$(OPENSSL_DIR)/libssl.a: $(OPENSSL_DIR)/configdata.pm
	@echo +++ libssl.a step
	cd $(OPENSSL_DIR) && EMCC_CFLAGS="$(OPENSSL_EMCC_CFLAGS)" $(EMMAKE) make libssl.a CFLAGS="$(OPENSSL_EMCC_CFLAGS)"

$(OPENSSL_DIR)/configdata.pm: gitmodules
	@echo +++ configdata.pm step
  ifneq ("$(wildcard $(OPENSSL_DIR)/configdata.pm)","")
	@echo +++ configdata.pm already exists
  else
	@echo +++ updating the openssl submodule, and generating configdata.pm now
	git submodule update --init --recursive
	cd $(OPENSSL_DIR) && ../scripts/emconfigure.sh
  endif

gitmodules: .gitmodules
	@echo +++ gitmodules step
#	git submodule update --init --recursive


# There seems to be interference between a dependency on config.status specified
# in the original GDAL Makefile and the config.status rule above that causes
# `make clean` from the gdal folder to try to _build_ gdal before cleaning it.
clean:
	cd $(OPENSSL_DIR) && git clean -X -d --force .
	rm -rf $(OUT_DIR)

##############
# Release    #
##############
release: $(VERSION).tar.gz $(VERSION).zip

$(VERSION).tar.gz $(VERSION).zip: dist/README dist/LICENSE.TXT dist/libcrypto.js dist/libcrypto.wasm dist/libcrypto.data
	tar czf $(VERSION).tar.gz dist
	zip -r $(VERSION).zip dist

dist/libcrypto.js dist/libcrypto.wasm dist/libcrypto.data: libcrypto.js
	cp libcrypto.JSPI.js libcrypto.JSPI.wasm libcrypto.data dist
