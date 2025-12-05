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

import libcrypto_JSPI from "../lib/libcrypto.JSPI.GITSHA.js";
import libcrypto_NO_JSPI from "../lib/libcrypto.NO-JSPI.GITSHA.js";

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
  async initialize_JSPI() {
    
    if (!this.init) {
      this.instance = (
        await libcrypto_JSPI(
          {
            memory: new WebAssembly.Memory({
              initial: 512,   //  32MB (i.e. 512 64k pages)
              maximum: 65536, //   4GB (i.e. 64k 64k pages)
            }),

            table: new WebAssembly.Table({ initial: 0, element: 'anyfunc' }),

            thisProgram: 'OpenZiti browZer',

            locateFile: function (path, scriptDirectory) {
              return path;
            },
          }
        )
      );

      this.init = true;

      let pstring = this.readString(this.instance, this.instance._whichWASMstring);
      // console.log('initialize_JSPI() whichWASMstring is: ', pstring);

      // Alloc data structures related to TLS data handling
      this.instance._fd_kv_alloc(this.instance);
    }
  }

  async initialize_NO_JSPI() {
    
    if (!this.init) {
      this.instance = (
        await libcrypto_NO_JSPI(
          {
            memory: new WebAssembly.Memory({
              initial: 512,   //  32MB (i.e. 512 64k pages)
              maximum: 65536, //   4GB (i.e. 64k 64k pages)
            }),

            table: new WebAssembly.Table({ initial: 0, element: 'anyfunc' }),

            thisProgram: 'OpenZiti browZer',

            locateFile: function (path, scriptDirectory) {
              return path;
            },
          }
        )
      );

      this.init = true;

      let pstring = this.readString(this.instance, this.instance._whichWASMstring);
      // console.log('initialize_NO_JSPI() whichWASMstring is: ', pstring);

      // Alloc data structures related to Inner-TLS data handling
      this.instance._fd_kv_alloc(this.instance);
    }
  }

 /**
  * Return WASM instance
  *
  * @function getWASMInstance
  */
  async getWASMInstance() {
    if (!this.init) throw Error("Not initialized; call .initialize_*() on LibCrypto");
    return this.instance;
  }

  
  validateWASMInstance( wasmInstance ) {
    if ( wasmInstance === this.instance) {
      return;
    }
    throw Error("invalid WASM instance specified");
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
  cleanupReferences(wasmInstance) {
    this.validateWASMInstance( wasmInstance );
    let { _destroyBuffer, _cleanup } = wasmInstance;
    while (this.mallocBufferAddresses.length) {
      _destroyBuffer(this.mallocBufferAddresses.pop());
    }
    _cleanup();
  }

  /**
   * Read UTF8 string from WASM memory location
   *
   * @function writeString
   * @param {number} memloc - Memory offset pointer
   * @return {string} UTF8 string
   */
  readString(wasmInstance, memloc) {
    let { maxRead } = this,
      _pstr = [],
      _char;
    let pview = new Uint8Array(wasmInstance.HEAPU8.buffer, memloc, maxRead);
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
  writeString(wasmInstance, str) {
    if (!str) return 0;
    let { _createBuffer } = wasmInstance;

    // if (typeof str !== "string") {
    //   str = str.toString(str instanceof Buffer ? "hex" : 16);
    // }

    const strBuf = new TextEncoder().encode(str + "\0");
    let offset = _createBuffer(strBuf.length);
    this.mallocBufferAddresses.push(offset);
    const outBuf = new Uint8Array(wasmInstance.HEAPU8.buffer, offset, strBuf.length);
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
  writeUint32Array(wasmInstance, uint32Array) {
    this.validateWASMInstance( wasmInstance );
    uint32Array.push(0);
    let { _createBuffer } = wasmInstance;
    let offset = _createBuffer(4 * uint32Array.length);
    this.mallocBufferAddresses.push(offset);
    new Uint32Array(wasmInstance.HEAPU8.buffer, offset, uint32Array.length).set(Uint32Array.from(uint32Array));

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
  // convertKey({
  //   key = null,
  //   curve = NID_secp521r1,
  //   outputtype = NID_X9_62_id_ecPublicKey,
  //   outformat = V_ASN1_BIT_STRING,
  //   compressed = POINT_CONVERSION_UNCOMPRESSED,
  //   password = null,
  // }) {
  //   if (key) {
  //     this.key = key;
  //   }
  //   if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
  //   let { keyHex } = this;
  //   let writeoffset = this.writeString(keyHex);
  //   let memorylocation = this.instance.convertKey(curve, writeoffset, outputtype, outformat, compressed, this.writeString(password));
  //   let pstring = this.readString(memorylocation);
  //   this.cleanupReferences(undefined);
  //   return pstring;
  // }

  /**
   * Generate an RSA key
   *
   * @function generateKey
   * @return {string} String representation of formatted key
   */
  generateKey(wasmInstance) {
    this.validateWASMInstance( wasmInstance );
    let memorylocation = wasmInstance._generateKey(EVP_PKEY_RSA);
    return memorylocation;
  }

  /**
   * Generate an EC key
   *
   * @function generateECKey
   * @return {string} String representation of formatted key
   */
  generateECKey( wasmInstance ) {
    this.validateWASMInstance( wasmInstance );
    let memorylocation = wasmInstance._generateECKey();
    return memorylocation;
  }

  /**
   * Get private key from an EC key
   *
   * @function getPrivateKeyPEM
   * @return {string} PEM representation of private key from specified EVP_PKEY
   */
  getPrivateKeyPEM(wasmInstance, pkey) {
    this.validateWASMInstance( wasmInstance );
    let memorylocation = wasmInstance._getPrivateKeyPEM(pkey);
    let pstring = this.readString(wasmInstance, memorylocation);
    this.cleanupReferences(wasmInstance);
    return pstring;
  }

  /**
   * Get public key from an EC key
   *
   * @function getPublicKeyPEM
   * @return {string} PEM representation of public key from specified EVP_PKEY
   */
  getPublicKeyPEM(wasmInstance, pkey) {
    this.validateWASMInstance( wasmInstance );
    let memorylocation = wasmInstance._getPublicKeyPEM(pkey);
    let pstring = this.readString(wasmInstance, memorylocation);
    this.cleanupReferences(wasmInstance);
    return pstring;
  }

  /**
   * Free an EC key
   *
   * @function freeECKey
   */
  // freeECKey(pkey) {
  //   if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
  //   this.instance.freeECKey(pkey);
  // }
    
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
  // createCertificate({
  //   key = null,
  //   curve = null,
  //   compressed = POINT_CONVERSION_UNCOMPRESSED,
  //   password = null,
  //   notBefore = 0,
  //   notAfter = 31536000,
  //   version = 3,
  //   issuer = "C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=ISSUER",
  //   name = "C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=NAME",
  //   id = 0,
  //   basicConstraints = { CA: false, pathlen: 0, critical: true },
  //   keyUsage = this.keyUsage,
  //   extKeyUsage = this.extKeyUsage,
  //   subjectAlternativeName = this.subjectAlternativeName,
  //   subjectKeyIdentifier = "hash",
  //   authorityKeyIdentifier = "keyid:always",
  //   friendlyName = null,
  //   certificateSigningRequest = null,
  //   outformat = NID_x509Certificate,
  //   caPEM = null,
  //   caCertificate = null,
  // }) {
  //   this.key = key;

  //   id = parseInt(id).toString();

  //   let { keyHex, calcKeyUsage } = this;

  //   let _san = [];

  //   for (let ext in subjectAlternativeName) {
  //     let sE = subjectAlternativeName[ext];
  //     if (sE instanceof Array && sE.length) {
  //       sE.forEach((a) => {
  //         _san.push(`${ext}:${a}`);
  //       });
  //     }
  //   }
  //   let _critical = certificateSigningRequest ? "" : "critical,";
  //   let extensions = new Map([
  //     [NID_subject_key_identifier, subjectKeyIdentifier],
  //     [NID_authority_key_identifier, authorityKeyIdentifier],
  //     [NID_basic_constraints, `${certificateSigningRequest || basicConstraints.critical ? "critical," : ""}${basicConstraints.CA ? "CA:TRUE" : "CA:FALSE"}${basicConstraints.CA ? `,pathlen:${basicConstraints.pathlen}` : ""}`],
  //     [NID_key_usage, _critical + (typeof keyUsage === "string" ? keyUsage : calcKeyUsage(keyUsage))],
  //     [NID_ext_key_usage, typeof extKeyUsage === "string" ? extKeyUsage : calcKeyUsage(extKeyUsage)],
  //     [NID_subject_alt_name, _san.join(",")],
  //   ]);

  //   let memLocCert = this.instance.createCertificate(
  //     curve,
  //     compressed,
  //     this.writeString(password),
  //     notBefore,
  //     notAfter,
  //     version - 1,
  //     ...[keyHex, name, issuer, id, friendlyName, certificateSigningRequest].map((a) => this.writeString(a)),
  //     this.writeUint32Array(
  //       [...extensions.entries()]
  //         .filter((a) => a[1].length)
  //         .map((a) => [a[0], this.writeString(a[1])])
  //         .flat()
  //     ),
  //     outformat,
  //     ...[caPEM, caCertificate].map((a) => this.writeString(a))
  //   );

  //   let certString = this.readString(memLocCert);
  //   this.cleanupReferences(undefined);
  //   return certString;
  // }

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
  createCertificateSigningRequest(wasmInstance, {
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
    this.validateWASMInstance( wasmInstance );
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

    let memLocCSR = wasmInstance._createCertificateSigningRequest(
      curve,
      compressed,
      this.writeString(password),
      version - 1,
      key,
      this.writeString(name),
      this.writeString(id),
      this.writeUint32Array(wasmInstance,
        [...extensions.entries()]
          .filter((a) => a[1].length)
          .map((a) => [a[0], this.writeString(a[1])])
          .flat()
      )
    );

    let certRequest = this.readString(wasmInstance, memLocCSR);

    this.cleanupReferences(wasmInstance);

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
   ssl_CTX_new( wasmInstance ) {
    this.validateWASMInstance( wasmInstance );
    let memorylocation = wasmInstance._ssl_CTX_new();
    return memorylocation;
  }

  /**
   * 
   * @param {*} ctx 
   * @param {*} pkey 
   * @returns 
   */
  ssl_CTX_add_private_key(wasmInstance, ctx, pkey) {
    this.validateWASMInstance( wasmInstance );
    let memorylocation = wasmInstance._ssl_CTX_add_private_key(ctx, pkey);
    return memorylocation;
  }

  /**
   * 
   * @param {*} ctx 
   * @param {*} certPem 
   * @returns 
   */
  ssl_CTX_add_certificate(wasmInstance, ctx, certPem) {
    this.validateWASMInstance( wasmInstance );

    let certPemPointer = this.writeString(wasmInstance, certPem);
    if (certPemPointer == 0) return null;

    let memorylocation = wasmInstance._ssl_CTX_add_certificate(ctx, certPemPointer);
    return memorylocation;
  }

  /**
   * 
   * @param {*} ctx 
   * @param {*} casPem 
   * @returns 
   */
  ssl_CTX_add1_to_CA_list(wasmInstance, ctx, casPem) {
    this.validateWASMInstance( wasmInstance );

    let casPemPointer = this.writeString(wasmInstance, casPem);
    if (casPemPointer == 0) return null;

    let memorylocation = wasmInstance._ssl_CTX_add1_to_CA_list(ctx, casPemPointer);
    return memorylocation;
  }


  /**
   * 
   * @param {*} ctx 
   * @param {*} casPem 
   * @returns 
   */
  ssl_CTX_add_extra_chain_cert(wasmInstance, ctx, certPem) {
    this.validateWASMInstance( wasmInstance );

    let certPemPointer = this.writeString(wasmInstance, certPem);
    if (certPemPointer == 0) return null;

    let memorylocation = wasmInstance._ssl_CTX_add_extra_chain_cert(ctx, certPemPointer);
    return memorylocation;
  }

  

  ssl_CTX_verify_certificate_and_key(wasmInstance, ctx) {
    this.validateWASMInstance( wasmInstance );
    let memorylocation = wasmInstance._ssl_CTX_verify_certificate_and_key(ctx);
    return memorylocation;
  }

  bio_new_ssl_connect(wasmInstance, ctx) {
    this.validateWASMInstance( wasmInstance );
    let memorylocation = wasmInstance._bio_new_ssl_connect(ctx);
    return memorylocation;
  }

  bio_do_connect(wasmInstance, bio) {
    this.validateWASMInstance( wasmInstance );
    let result = wasmInstance._bio_do_connect(bio);
    return result;
  }


  ssl_new(wasmInstance, ctx) {
    this.validateWASMInstance( wasmInstance );
    let memorylocation = wasmInstance._ssl_new(ctx);
    return memorylocation;
  }

  // bio_new_ssl_connect(ctx) {
  //   if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
  //   let memorylocation = this.instance.bio_new_ssl_connect(ctx);
  //   return memorylocation;
  // }

  bio_get_ssl(wasmInstance, sbio) {
    this.validateWASMInstance( wasmInstance );
    let memorylocation = wasmInstance._bio_get_ssl(sbio);
    return memorylocation;
  }

  bio_set_conn_hostname(wasmInstance, sbio, conn_str) {
    this.validateWASMInstance( wasmInstance );

    let hostnamePointer = this.writeString(wasmInstance, conn_str);

    let result = wasmInstance._bio_set_conn_hostname(sbio, hostnamePointer);
    return result;
  }

  async ssl_do_handshake(wasmInstance, ssl) {
    this.validateWASMInstance( wasmInstance );
    // console.log('index.js calling wasmInstance.ssl_do_handshake() ssl is: ', ssl);
    let result = await wasmInstance._ssl_do_handshake(ssl);
    // console.log('index.js returned from wasmInstance.ssl_do_handshake() result is: ', result);
    return result;
  }

  ssl_is_init_finished(wasmInstance, ssl) {
    this.validateWASMInstance( wasmInstance );
    let result = wasmInstance._SSL_is_init_finished(ssl);
    return result;
  }



  ssl_get_verify_result(wasmInstance, ssl) {
    this.validateWASMInstance( wasmInstance );
    let result = wasmInstance._ssl_get_verify_result(ssl);
    return result;
  }

  fd_kv_alloc(wasmInstance) {
    this.validateWASMInstance( wasmInstance );
    wasmInstance._fd_kv_alloc();
  }

  /**
   *  
   */
   tls_enqueue(wasmInstance, fd, jsArrayBuffer) {

    this.validateWASMInstance( wasmInstance );

    // console.log(`tls_enqueue() entered: fd[${fd}]`);

    let { memory } = wasmInstance;
    
    let tlsDataQueue = wasmInstance._fd_kv_getItem(fd);

    // if there isn't a TLSDataQueue for the specified FD...then allocate one
    if (!tlsDataQueue) {
      tlsDataQueue = wasmInstance._constructTLSDataQueue( fd, 64 );
      wasmInstance._fd_kv_addItem(fd, tlsDataQueue);
    }

    // Copy the incoming chunk of encrypted data from JS memory into WASM memory
    let wasmArrayPtr = wasmInstance._allocateTLSDataBuf(jsArrayBuffer.byteLength);
    let wasmArray = new Uint8Array(wasmInstance.HEAPU8.buffer, wasmArrayPtr, jsArrayBuffer.byteLength);
    let dataArray = new Uint8Array(jsArrayBuffer);
    wasmArray.set(dataArray); // Add the chunk of encrypted data to the queue of data awaiting decryption for this FD
    let result = wasmInstance._enqueueTLSData(tlsDataQueue, wasmArrayPtr, jsArrayBuffer.byteLength);
    // console.log('tls_enqueue() wasmInstance.enqueueTLSData returned: ', result);
  }

  /**
   *  
   */
  peekTLSData(wasmInstance, fd) {

    this.validateWASMInstance( wasmInstance );
    
    let tlsDataQueue = wasmInstance._fd_kv_getItem(fd);

    if (!tlsDataQueue) {
      return null;
    }

    return wasmInstance._peekTLSData(tlsDataQueue);
  }

  tls_write(wasmInstance, ssl, jsArrayBuffer) {

    this.validateWASMInstance( wasmInstance );

    // let { memory } = wasmInstance;

    // console.log('tls_write() ssl is: ', ssl);
    // console.log('tls_write() jsArrayBuffer is: ', jsArrayBuffer);
    // console.log('tls_write() jsArrayBuffer.byteLength is: ', jsArrayBuffer.byteLength);

    let wasmArrayPtr = wasmInstance._allocateTLSDataBuf(jsArrayBuffer.byteLength);
    // console.log('tls_write() memory.buffer is: ', wasmInstance.HEAPU8.buffer);
    // console.log('tls_write() wasmArrayPtr is: ', wasmArrayPtr);
    let wasmArray = new Uint8Array(wasmInstance.HEAPU8.buffer, wasmArrayPtr, jsArrayBuffer.byteLength);
    let dataArray = new Uint8Array(jsArrayBuffer);
    wasmArray.set(dataArray);
    // console.log('tls_write() wasmArray is: ', wasmArray);
    
    let result = wasmInstance._tls_write(ssl, wasmArrayPtr, jsArrayBuffer.byteLength);

    // console.log('tls_write() result is: ', result);

    return result;
  }

  async tls_read(wasmInstance, ssl) {
    this.validateWASMInstance( wasmInstance );

    // console.log('tls_read() ssl is: ', ssl);

    // let { memory } = wasmInstance;

    let len = 64 * 1024;

    let wasmArrayPtr = wasmInstance._allocateTLSDataBuf( len );

    let read_len = await wasmInstance._tls_read(ssl, wasmArrayPtr, len);

    if (read_len < 0) {
      let fd = await wasmInstance._SSL_get_fd(ssl);
      console.log('tls_read() wasmInstance._tls_read failed, returned [%d] for fd[%d] ', read_len, fd);
    }

    // Copy WASM memory to JavaScript memory
    let jsArray = new Uint8Array(read_len); // alloc new JS array
    let wasmArray = new Uint8Array(wasmInstance.HEAPU8.buffer, wasmArrayPtr, read_len);  // Get a view of the wasm array
    jsArray.set(wasmArray); // copy wasm -> js

    wasmInstance._freeTLSDataBuf( wasmArrayPtr );

    return jsArray;
  }


  ssl_set_fd(wasmInstance, ssl, socket) {
    this.validateWASMInstance( wasmInstance );
    let result = wasmInstance._ssl_set_fd(ssl, socket);
    return result;
  }

  ssl_connect(wasmInstance, ssl) {
    this.validateWASMInstance( wasmInstance );
    let result = wasmInstance._ssl_connect(ssl);
    return result;
  }
}

export {
  LibCrypto
};

