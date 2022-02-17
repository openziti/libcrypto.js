/**
 *
 */



/**
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
    let array = new Uint8Array(this.instance.memory.buffer, buf, buflen);
    crypto.getRandomValues(array);
    // console.log("ziti_getentropy() crypto.getRandomValues produced: ", array);
  },

  __syscall_prlimit64: function( pid, resource, new_limit, old_limit)  {
    console.log("__syscall_prlimit64(): args are: ", pid, resource, new_limit, old_limit);
    return 0;
  },
  __syscall_ugetrlimit: function( resource, rlim) {
    console.log("__syscall_ugetrlimit(): args are: ", resource, rlim);
    return 0;
  },
  __syscall_setrlimit: function( resource, rlim) {
    console.log("__syscall_setrlimit(): args are: ", resource, rlim);
    return 0;
  },

});

