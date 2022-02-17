/**
 *
 * Implements a C API in JavaScript
 * 
 * It is possible to implement a C API in JavaScript! This is the approach used in many 
 * of Emscripten’s libraries, like SDL1 and OpenGL. We use it to write our own APIs that 
 * will be called from the OpenSSL C code. To do this we define the interface, decorating 
 * with 'extern' to mark the methods in the API as external symbols. We then implement the 
 * symbols in JavaScript (below). When compiling/linking the OpenSSL C code, the emcc compiler 
 * looks in the JavaScript libraries for relevant external symbols.  Below, any functions 
 * we define will be added to teh emcc libraries via the 'mergeInto' mechanism.
 */


mergeInto(LibraryManager.library, {

  /**
   * @function ziti_getentropy
   * 
   * When OpenSSL is cross-compiled into WebAssembly, it will link with this JS function
   * in order to obtain entropy.  We utilize the browser's 'crypto' mechanism to generate 
   * the random bytes.
   * 
   * @param {*} buf address within WASM heap to write random bytes
   * @param {*} buflen length of buffer within WASM heap
   */
  ziti_getentropy: function (buf, buflen) {
    let array = new Uint8Array(Module.HEAPU8.buffer, buf, buflen);
    crypto.getRandomValues(array);
  },

  /**
   * 
   * @param {*} pid 
   * @param {*} resource 
   * @param {*} new_limit 
   * @param {*} old_limit 
   * @returns 
   */
  __syscall_prlimit64: function( pid, resource, new_limit, old_limit)  {
    console.log("__syscall_prlimit64(): args are: ", pid, resource, new_limit, old_limit);
    return 0;
  },

  /**
   * 
   * @param {*} resource 
   * @param {*} rlim 
   * @returns 
   */
  __syscall_ugetrlimit: function( resource, rlim) {
    console.log("__syscall_ugetrlimit(): args are: ", resource, rlim);
    return 0;
  },

  /**
   * 
   * @param {*} resource 
   * @param {*} rlim 
   * @returns 
   */
  __syscall_setrlimit: function( resource, rlim) {
    console.log("__syscall_setrlimit(): args are: ", resource, rlim);
    return 0;
  },

});

