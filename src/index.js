/*
Copyright Netfoundry, Inc.

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

import libcryptoWASM from "../lib/libcrypto.wasm.js";

/**
 *
 * Class representing a LibCrypto instance.
 *
 */
class LibCrypto {

  /**
   *  LibCrypto ctor
   */
  constructor() {

    this.mallocBufferAddresses = [];
    this.wasi = null;
    this.wasiBytes = null;
    this.instance = null;
    this.init = false;
    this.key = null;
    this.maxRead = 1024*64;
  
   /**
    * The key usage extension defines the purpose (e.g., encipherment,
    * signature, certificate signing) of the key contained in the
    * certificate.
    *
    * {@link https://tools.ietf.org/html/rfc5280#section-4.2.1.3}
    * @namespace
    * @property {Boolean} digitalSignature - Subject Public Key (SPK) is used for verifying digital signatures
    * @property {Boolean} nonRepudiation - SPK used to verify digital signatures
    * @property {Boolean} keyEncipherment - SPK used for enciphering private or secret keys
    * @property {Boolean} dataEncipherment - SPK used for enciphering raw user data w/o an intermediate symmetric cipher
    * @property {Boolean} keyAgreement - SPK used for key agreement, used with encipherOnly / decipherOnly
    * @property {Boolean} keyCertSign - SPK used for verifying signatures on public key certificates
    * @property {Boolean} cRLSign - SPK used for verifying signatures on certificate revocation lists
    * @property {Boolean} encipherOnly - If keyAgreement set, enciphering data while performing key agreement
    * @property {Boolean} decipherOnly - If keyAgreement set, deciphering data while performing key agreement
    */
    this.keyUsage = {
      digitalSignature: false,
      nonRepudiation: false,
      keyEncipherment: false,
      dataEncipherment: false,
      keyAgreement: false,
      keyCertSign: false,
      cRLSign: false,
      encipherOnly: false,
      decipherOnly: false,
    };

    /**
     * This extension indicates one or more purposes for which the certified
     * public key may be used, in addition to or in place of the basic
     * purposes indicated in the key usage extension
     *
     * {@link https://tools.ietf.org/html/rfc5280#section-4.2.1.12}
     * {@link https://tools.ietf.org/html/rfc6071#section-2.4}
     *
     * @namespace
     * @property {Boolean} serverAuth - TLS WWW server authentication
     * @property {Boolean} clientAuth - TLS WWW server authentication
     * @property {Boolean} codeSigning - Signing of downloadable executable code
     * @property {Boolean} emailProtection - Email protection
     * @property {Boolean} timeStamping - Binding the hash of an object to a time
     * @property {Boolean} OCSPSigning - Signing OCSP responses
     * @property {Boolean} ipsecIKE - Used for IP Security (IPsec) and Internet Key Exchange (IKE)
     * @property {Boolean} msCodeInd - Microsoft Individual Code Signing (authenticode)
     * @property {Boolean} msCodeCom - Microsoft Commercial Code Signing (authenticode)
     * @property {Boolean} msCTLSign - Microsoft Trust List Signing
     * @property {Boolean} msEFS - Microsoft Encrypting File System
     */
    this.extKeyUsage = {
      serverAuth: false,
      clientAuth: false,
      codeSigning: false,
      emailProtection: false,
      timeStamping: false,
      OCSPSigning: false,
      ipsecIKE: false,
      msCodeInd: false,
      msCodeCom: false,
      msCTLSign: false,
      msEFS: false,
    };

    /**
     * The subject alternative name extension allows identities to be bound
     * to the subject of the certificate.
     *
     * {@link https://tools.ietf.org/html/rfc5280#section-4.2.1.6}
     */
    this.subjectAlternativeName = {
      URI: [],
      DNS: [],
      IP: [],
      email: [],
    };

  }

  /**
   * Initialize the LibCrypto instance.
   * Compiles the core WebAssembly System Interface (WASI) compliant WebAssembly binary.
   *
   * @async
   * @function initialize
   * @return {undefined}
   */
  async initialize() {
    
    if (!this.init) {
      this.instance = libcryptoWASM;
      this.instance = (
        await libcryptoWASM(
          {
            memory: new WebAssembly.Memory({
              initial: 512,   //  32MB (i.e. 512 64k pages)
              maximum: 65536, //   4GB (i.e. 64k 64k pages)
            }),

            table: new WebAssembly.Table({ initial: 0, element: 'anyfunc' }),

            thisProgram: 'OpenZiti browZer',

          }
        )
      ).asm;

      this.init = true;

      // Alloc data structures related to TLS data handling
      this.fd_kv_alloc();
    }
  }

  /**
   * Creates the Key Usage comma-separated string from an object of NID parameters.
   *
   * @function calcKeyUsage
   * @param {object} KU - Object with NID as parameters.
   * @return {string} The comma-separated list of NIDs
   */
  calcKeyUsage = (KU) =>
    Object.entries(KU)
      .filter((kU) => kU[1])
      .map((kU) => kU[0])
      .join(",");

  /**
   * Memory management for buffers
   *
   * @function cleanupReferences
   * @return {undefined}
   */
  cleanupReferences() {
    let { destroyBuffer, cleanup } = this.instance;
    while (this.mallocBufferAddresses.length) {
      destroyBuffer(this.mallocBufferAddresses.pop());
    }
    cleanup();
  }

  /**
   * Read UTF8 string from WASM memory location
   *
   * @function writeString
   * @param {number} memloc - Memory offset pointer
   * @return {string} UTF8 string
   */
  readString(memloc) {
    let { maxRead } = this,
      _pstr = [],
      _char;
    let pview = new Uint8Array(this.instance.memory.buffer, memloc, maxRead);
    while ((_char = pview[_pstr.length]) && _pstr.length < maxRead) _pstr.push(_char);
    let result = new TextDecoder().decode(new Uint8Array(_pstr));
    if (result.match(/[0-9a-fA-F]{2}:/) && result.match(/:/g).length > result.length / 4) {
      result = result.replace(/:/g, "");
    }
    return result;
  }

  /**
   * Write UTF8 string to WASM memory location
   *
   * @function writeString
   * @param {string} str - String to write to memory location
   * @return {number} Memory offset pointer
   */
  writeString(str) {
    if (!str) return 0;
    let { createBuffer, memory } = this.instance;

    // if (typeof str !== "string") {
    //   str = str.toString(str instanceof Buffer ? "hex" : 16);
    // }

    const strBuf = new TextEncoder().encode(str + "\0");
    let offset = createBuffer(strBuf.length);
    this.mallocBufferAddresses.push(offset);
    const outBuf = new Uint8Array(memory.buffer, offset, strBuf.length);
    for (let i = 0; i < strBuf.length; i++) {
      outBuf[i] = strBuf[i];
    }
    return offset;
  }

  /**
   * Write an array of 32-bit unsigned integers to WASM memory location
   *
   * @function writeUint32Array
   * @param {Uint32Array} uint32Array - array of 32-bit unsigned integers to write to wasm memory
   * @return {number} Memory offset pointer
   */
  writeUint32Array(uint32Array) {
    uint32Array.push(0);
    let { createBuffer, memory } = this.instance;
    let offset = createBuffer(4 * uint32Array.length);
    this.mallocBufferAddresses.push(offset);
    new Uint32Array(memory.buffer, offset, uint32Array.length).set(Uint32Array.from(uint32Array));

    return offset;
  }

  /**
   * Load key from Buffer
   *
   * @function loadKey
   * @param {Buffer|ArrayBuffer|string|string[]|Object} [key=buffer] - Buffer to load
   * @return {number} Memory offset pointer
   */
  loadKey(key = Buffer.from([])) {
    if (!(key instanceof Buffer)) {
      key = Buffer.from(key);
    }
    this.key = key;
  }

  /**
   * The keyHex property is the current key in hexidecimal
   *
   * @type {string}
   * @return {string} Current key in hexidecimal
   */
  get keyHex() {
    return this.key ? this.key.toString("hex") : null;
  }

  /**
   * Convert key to serialization format
   *
   * @function convertKey
   * @param {Object} settings - The configuration object to tell OpenSSL how to format the key
   * @param {Buffer|ArrayBuffer|string|string[]|Object} [settings.key=null] - Key, default is current instance key. If not null, replaces key.
   * @param {number} [settings.curve=NID_secp521r1] - Numerical ID (NID) for the Elliptic Curve (EC) to use
   * @param {number} [settings.outputtype=NID_X9_62_id_ecPublicKey] - NID for OpenSSL output type
   * @param {number} [settings.outformat=V_ASN1_BIT_STRING] - NID for OpenSSL output format
   * @param {number} [settings.compressed=POINT_CONVERSION_UNCOMPRESSED] - Which X9.62 (ECDSA) form, for encoding an EC point
   * @param {string} [settings.password=null] - Password to use
   * @return {string} String representation of formatted key
   */
  convertKey({
    key = null,
    curve = NID_secp521r1,
    outputtype = NID_X9_62_id_ecPublicKey,
    outformat = V_ASN1_BIT_STRING,
    compressed = POINT_CONVERSION_UNCOMPRESSED,
    password = null,
  }) {
    if (key) {
      this.key = key;
    }
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let { keyHex } = this;
    let writeoffset = this.writeString(keyHex);
    let memorylocation = this.instance.convertKey(curve, writeoffset, outputtype, outformat, compressed, this.writeString(password));
    let pstring = this.readString(memorylocation);
    this.cleanupReferences();
    return pstring;
  }

  /**
   * Generate an RSA key
   *
   * @function generateKey
   * @return {string} String representation of formatted key
   */
  generateKey({
    /* no parms yet */
  }) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.generateKey(EVP_PKEY_RSA);
    return memorylocation;
  }

  /**
   * Generate an EC key
   *
   * @function generateECKey
   * @return {string} String representation of formatted key
   */
  generateECKey({
    /* no parms yet */
  }) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.generateECKey();
    return memorylocation;
  }

  /**
   * Get private key from an EC key
   *
   * @function getPrivateKeyPEM
   * @return {string} PEM representation of private key from specified EVP_PKEY
   */
  getPrivateKeyPEM(pkey) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.getPrivateKeyPEM(pkey);
    let pstring = this.readString(memorylocation);
    this.cleanupReferences();
    return pstring;
  }

  /**
   * Get public key from an EC key
   *
   * @function getPublicKeyPEM
   * @return {string} PEM representation of public key from specified EVP_PKEY
   */
    getPublicKeyPEM(pkey) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.getPublicKeyPEM(pkey);
    let pstring = this.readString(memorylocation);
    this.cleanupReferences();
    return pstring;
  }

  /**
   * Free an EC key
   *
   * @function freeECKey
   */
    freeECKey(pkey) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    this.instance.freeECKey(pkey);
  }
    
  /**
   * Create a certificate
   *
   * @function createCertificate
   * @param {Object} settings - The configuration object to tell OpenSSL how to format the key
   * @param {Buffer|ArrayBuffer|string|string[]|Object} [settings.key=null] - Key, default is current instance key. If not null, replaces key.
   * @param {number} [settings.curve=NID_secp521r1] - Numerical ID (NID) for the Elliptic Curve (EC) to use
   * @param {number} [settings.compressed=POINT_CONVERSION_UNCOMPRESSED] - Which X9.62 (ECDSA) form, for encoding an EC point
   * @param {string} [settings.password=null] - Password to use
   * @param {number} [settings.notBefore=0] - Certificate validity start in seconds from current system time
   * @param {number} [settings.notAfter=31536000] - Certificate validity stop in seconds from current system time
   * @param {number} [settings.version=3] - Certificate version
   * @param {string} [settings.issuer=C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=ISSUER] - Certificate issuer csv Distinguished Name (DN) string
   * @param {string} [settings.name=C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=NAME] - Certificate name csv Distinguished Name (DN) string
   * @param {number} [settings.id=0] - Certificate ID number
   * @param {Object} settings.basicConstraints - Basic constraints on this certificate
   * @param {Boolean} settings.basicConstraints.CA - The subject of the cert is a CA
   * @param {number} settings.basicConstraints.pathlen -  The max depth of valid cert paths that include cert
   * @param {Object|string} [settings.keyUsage=this.keyUsage] - Key usage extensions.
   * @param {Object|string} [settings.extKeyUsage=this.extKeyUsage] - Extended Key usage extensions.
   * @param {Object} [settings.subjectAlternativeName] - Object with properties enumerating SAN (additional host names) for certificate
   * @param {string} [settings.subjectKeyIdentifier=hash"] - Either hash per {@link https://tools.ietf.org/html/rfc3280#section-4.2.1.2} or a hex string (strongly discouraged).
   * @param {string} [settings.authorityKeyIdentifier=keyid:always] - {@link https://www.openssl.org/docs/man1.0.2/man5/x509v3_config.html} Can be either 'keyid', 'issuer', or both, each with optional value 'always'
   * @param {string} [settings.friendlyName=null] - Friendly Name for Microsoft .p12
   * @param {string} [settings.certificateSigningRequest=null] - CSR as a string
   * @param {number} [settings.outformat=NID_x509Certificate] - NID for the output format
   * @param {number} [settings.caPEM=null] - PEM of Certificate Authority for signing
   * @param {number} [settings.caCertificate=null] - CA Certificate
   * @return {string} String representation of certificate
   */
  createCertificate({
    key = null,
    curve = null,
    compressed = POINT_CONVERSION_UNCOMPRESSED,
    password = null,
    notBefore = 0,
    notAfter = 31536000,
    version = 3,
    issuer = "C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=ISSUER",
    name = "C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=NAME",
    id = 0,
    basicConstraints = { CA: false, pathlen: 0, critical: true },
    keyUsage = this.keyUsage,
    extKeyUsage = this.extKeyUsage,
    subjectAlternativeName = this.subjectAlternativeName,
    subjectKeyIdentifier = "hash",
    authorityKeyIdentifier = "keyid:always",
    friendlyName = null,
    certificateSigningRequest = null,
    outformat = NID_x509Certificate,
    caPEM = null,
    caCertificate = null,
  }) {
    this.key = key;

    id = parseInt(id).toString();

    let { keyHex, calcKeyUsage } = this;

    let _san = [];

    for (let ext in subjectAlternativeName) {
      let sE = subjectAlternativeName[ext];
      if (sE instanceof Array && sE.length) {
        sE.forEach((a) => {
          _san.push(`${ext}:${a}`);
        });
      }
    }
    let _critical = certificateSigningRequest ? "" : "critical,";
    let extensions = new Map([
      [NID_subject_key_identifier, subjectKeyIdentifier],
      [NID_authority_key_identifier, authorityKeyIdentifier],
      [NID_basic_constraints, `${certificateSigningRequest || basicConstraints.critical ? "critical," : ""}${basicConstraints.CA ? "CA:TRUE" : "CA:FALSE"}${basicConstraints.CA ? `,pathlen:${basicConstraints.pathlen}` : ""}`],
      [NID_key_usage, _critical + (typeof keyUsage === "string" ? keyUsage : calcKeyUsage(keyUsage))],
      [NID_ext_key_usage, typeof extKeyUsage === "string" ? extKeyUsage : calcKeyUsage(extKeyUsage)],
      [NID_subject_alt_name, _san.join(",")],
    ]);

    let memLocCert = this.instance.createCertificate(
      curve,
      compressed,
      this.writeString(password),
      notBefore,
      notAfter,
      version - 1,
      ...[keyHex, name, issuer, id, friendlyName, certificateSigningRequest].map((a) => this.writeString(a)),
      this.writeUint32Array(
        [...extensions.entries()]
          .filter((a) => a[1].length)
          .map((a) => [a[0], this.writeString(a[1])])
          .flat()
      ),
      outformat,
      ...[caPEM, caCertificate].map((a) => this.writeString(a))
    );

    let certString = this.readString(memLocCert);
    this.cleanupReferences();
    return certString;
  }

  /**
   * Create a certificate signing request
   *
   * @function createCertificateSigningRequest
   * @param {Object} settings - The configuration object to tell OpenSSL how to format the key
   * @param {Buffer|ArrayBuffer|string|string[]|Object} [settings.key=null] - Key, default is current instance key. If not null, replaces key.
   * @param {number} [settings.curve=NID_secp521r1] - Numerical ID (NID) for the Elliptic Curve (EC) to use
   * @param {number} [settings.compressed=POINT_CONVERSION_UNCOMPRESSED] - Which X9.62 (ECDSA) form, for encoding an EC point
   * @param {string} [settings.password=null] - Password to use
   * @param {number} [settings.version=3] - Certificate version
   * @param {string} [settings.name=C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=NAME] - Certificate name csv Distinguished Name (DN) string
   * @param {number} [settings.id=0] - Certificate ID number
   * @param {Object} settings.basicConstraints - Basic constraints on this certificate
   * @param {Object|string} [settings.keyUsage=this.keyUsage] - Key usage extensions.
   * @param {Object|string} [settings.extKeyUsage=this.extKeyUsage] - Extended Key usage extensions.
   * @param {Object} [settings.subjectAlternativeName] - Object with properties enumerating SAN (additional host names) for certificate
   * @param {string} [settings.subjectKeyIdentifier=hash] - Either hash per {@link https://tools.ietf.org/html/rfc3280#section-4.2.1.2} or a hex string (strongly discouraged).
   * @return {string} String representation of certificate
   */
    createCertificateSigningRequest({
    key = null,
    curve = NID_secp521r1,
    compressed = POINT_CONVERSION_UNCOMPRESSED,
    password = null,
    version = 1,
    name = "C=US, ST=NC, L=DZM, O=OpenZiti, OU=browZer, CN=OTF",
    id = "0",
    basicConstraints = null,
    keyUsage = this.keyUsage,
    extKeyUsage = this.extKeyUsage,
    subjectAlternativeName = this.subjectAlternativeName,
    subjectKeyIdentifier = null,
  }) {
    if (key) {
      this.key = key;
    }
    let { keyHex, calcKeyUsage } = this;

    let _san = [];

    for (let ext in subjectAlternativeName) {
      let sE = subjectAlternativeName[ext];
      if (sE instanceof Array && sE.length) {
        sE.forEach((a) => {
          _san.push(`${ext}:${a}`);
        });
      }
    }

    let extensions = new Map([

    ]); //TODO requested extensions

    let memLocCSR = this.instance.createCertificateSigningRequest(
      curve,
      compressed,
      this.writeString(password),
      version - 1,
      key,
      this.writeString(name),
      this.writeString(id),
      this.writeUint32Array(
        [...extensions.entries()]
          .filter((a) => a[1].length)
          .map((a) => [a[0], this.writeString(a[1])])
          .flat()
      )
    );

    let certRequest = this.readString(memLocCSR);

    this.cleanupReferences();

    return certRequest;
  }

  /**
   * Range Check Private Key
   *
   * @function validPrivateKey
   * @static
   * @param {Buffer|ArrayBuffer|string|string[]|Object} privateKey - Private Key to compare
   * @param {string} [min=0] - Minimum value as a hex string
   * @param {string} [max=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140] - Maximum value as a hex string
   * @return {Boolean}
   */
  static validPrivateKey(privateKey, min = "0", max = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140") {
    if (!(privateKey instanceof Buffer)) {
      privateKey = Buffer.from(privateKey);
    }
    max = Buffer.from(max, "hex");
    min = Buffer.from(min, "hex");
    return Buffer.compare(max, privateKey) === 1 && Buffer.compare(privateKey, min) === 1;
  }

  /**
   * Create a new SSL_CTX object, which holds various configuration and data relevant to SSL/TLS or DTLS session establishment
   *
   * @function ssl_CTX_new
   */
   ssl_CTX_new() {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.ssl_CTX_new();
    return memorylocation;
  }

  /**
   * 
   * @param {*} ctx 
   * @param {*} pkey 
   * @returns 
   */
  ssl_CTX_add_private_key(ctx, pkey) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.ssl_CTX_add_private_key(ctx, pkey);
    return memorylocation;
  }

  /**
   * 
   * @param {*} ctx 
   * @param {*} certPem 
   * @returns 
   */
  ssl_CTX_add_certificate(ctx, certPem) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");

    let certPemPointer = this.writeString(certPem);
    if (certPemPointer == 0) return null;

    let memorylocation = this.instance.ssl_CTX_add_certificate(ctx, certPemPointer);
    return memorylocation;
  }

  /**
   * 
   * @param {*} ctx 
   * @param {*} casPem 
   * @returns 
   */
  ssl_CTX_add1_to_CA_list(ctx, casPem) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");

    let casPemPointer = this.writeString(casPem);
    if (casPemPointer == 0) return null;

    let memorylocation = this.instance.ssl_CTX_add1_to_CA_list(ctx, casPemPointer);
    return memorylocation;
  }


  /**
   * 
   * @param {*} ctx 
   * @param {*} casPem 
   * @returns 
   */
   ssl_CTX_add_extra_chain_cert(ctx, casPem) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");

    let casPemPointer = this.writeString(casPem);
    if (casPemPointer == 0) return null;

    let memorylocation = this.instance.ssl_CTX_add_extra_chain_cert(ctx, casPemPointer);
    return memorylocation;
  }

  

  ssl_CTX_verify_certificate_and_key(ctx) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.ssl_CTX_verify_certificate_and_key(ctx);
    return memorylocation;
  }

  bio_new_ssl_connect(ctx) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.bio_new_ssl_connect(ctx);
    return memorylocation;
  }

  bio_do_connect(bio) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let result = this.instance.bio_do_connect(bio);
    return result;
  }


  ssl_new(ctx) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.ssl_new(ctx);
    return memorylocation;
  }

  bio_new_ssl_connect(ctx) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.bio_new_ssl_connect(ctx);
    return memorylocation;
  }

  bio_get_ssl(sbio) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let memorylocation = this.instance.bio_get_ssl(sbio);
    return memorylocation;
  }

  bio_set_conn_hostname(sbio, conn_str) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");

    let hostnamePointer = this.writeString(conn_str);

    let result = this.instance.bio_set_conn_hostname(sbio, hostnamePointer);
    return result;
  }

  ssl_do_handshake(ssl) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let result = this.instance.ssl_do_handshake(ssl);
    return result;
  }

  ssl_get_verify_result(ssl) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let result = this.instance.ssl_get_verify_result(ssl);
    return result;
  }

  fd_kv_alloc() {
    this.instance.fd_kv_alloc();
  }

  /**
   *  
   */
   tls_enqueue(fd, jsArrayBuffer) {

    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");

    console.log('tls_enqueue() entered: fd: ', fd);

    let { createBuffer, memory } = this.instance;
    
    let tlsDataQueue = this.instance.fd_kv_getItem(fd);

    // if there isn't a TLSDataQueue for the specified FD...then allocate one
    if (!tlsDataQueue) {
      tlsDataQueue = this.instance.constructTLSDataQueue( fd, 64 );
      this.instance.fd_kv_addItem(fd, tlsDataQueue);
    }

    // Copy the incoming chunk of encrypted data from JS memory into WASM memory
    // let wasmArrayPtr = createBuffer(jsArrayBuffer.byteLength);
    let wasmArrayPtr = this.instance.allocateTLSDataBuf(jsArrayBuffer.byteLength);
    let wasmArray = new Uint8Array(memory.buffer, wasmArrayPtr, jsArrayBuffer.byteLength);
    let dataArray = new Uint8Array(jsArrayBuffer);
    wasmArray.set(dataArray); // Add the chunk of encrypted data to the queue of data awaiting decryption for this FD
    this.instance.enqueueTLSData(tlsDataQueue, wasmArrayPtr, jsArrayBuffer.byteLength);
  }

  tls_write(ssl, buffer) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");

    let { createBuffer, destroyBuffer, memory } = this.instance;

    let offset = createBuffer(buffer.byteLength);

    // Transfer the bytes into the WebAssembly heap
    let ndx = 0;
    let dataview = new DataView(buffer, ndx);
    let outBuf = new Uint8Array(memory.buffer, offset, buffer.byteLength);
    while (ndx < buffer.byteLength) {
        let byte = dataview.getUint8(ndx);
        outBuf[ndx] = byte;
        ndx++;
    }
    
    let result = this.instance.tls_write(ssl, offset, buffer.byteLength);

    // destroyBuffer( offset );

    return result;
  }

  tls_read(ssl) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");

    let { memory } = this.instance;

    let len = 64 * 1024;

    let wasmArrayPtr = this.instance.allocateTLSDataBuf( len );

    let read_len = this.instance.tls_read(ssl, wasmArrayPtr, len);

    // Copy WASM memory to JavaScript memory
    let jsArray = new Uint8Array(read_len); // alloc new JS array
    let wasmArray = new Uint8Array(memory.buffer, wasmArrayPtr, read_len);  // Get a view of the wasm array
    jsArray.set(wasmArray); // copy wasm -> js

    this.instance.freeTLSDataBuf( wasmArrayPtr );

    return jsArray;
  }


  ssl_set_fd(ssl, socket) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let result = this.instance.ssl_set_fd(ssl, socket);
    return result;
  }

  ssl_connect(ssl) {
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let result = this.instance.ssl_connect(ssl);
    return result;
  }
}

export {
  LibCrypto
};

