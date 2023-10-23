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

  emscripten_stack_init: function() {
    console.log("emscripten_stack_init(): entered");
  },

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

  __syscall_setsockopt: function(arg1, arg2, arg3, arg4, arg5) {
    console.log("__syscall_setsockopt(): args are: ", arg1, arg2, arg3, arg4, arg5);
    return 0;
  },

  __syscall_getegid32: function() {
    return 0;
  },
  __syscall_geteuid32: function() {
    return 0;
  },
  __syscall_getgid32: function() {
    return 0;
  },
  __syscall_getuid32: function() {
    return 0;
  },
  __syscall_connect: function() {
    return 0;
  },
  __syscall_getsockopt: function (fd, level, optname, optval, optlen, d1) {
    return -50;
  },
  __syscall_shutdown: function (fd, how) {
    return -50;
  },

  _gai_strerror: function(arg1) {
    console.log("_gai_strerror(): args are: ", arg1);
    return '';
  },
  gai_strerror: function(arg1) {
    console.log("gai_strerror(): args are: ", arg1);
    return '';
  },
  __gai_strerror: function(arg1) {
    console.log("__gai_strerror(): args are: ", arg1);
    return '';
  },
  
  /**
   * 
   */
  read: function(s, outbuf, len) {
    console.log("read(): args are: ", s, outbuf, len);
    debugger
  },
  _read: function(s, outbuf, len) {
    console.log("_read(): args are: ", s, outbuf, len);
    debugger
  },

  /**
   * 
   * @param {*} fd 
   * @param {*} iov 
   * @param {*} iovcnt 
   * @param {*} pnum 
   * @returns 
   */
  fd_read: async function (fd, iov, iovcnt, pnum) {

    console.log('fd_read: entered');

    if (fd < 10) {  // If not a ziti-browzer-core ZitiChannel fd
      var stream = SYSCALLS.getStreamFromFD(fd);
      var num = SYSCALLS.doReadv(stream, iov, iovcnt);
      HEAP32[pnum >> 2] = num;
      return 0;
    }

    else {  // OK, we've got a ziti-browzer-core ZitiChannel fd, so find the associated ZitiChannel

      const wasmFD = _zitiContext._wasmFDsById.get( fd );
      if (wasmFD === null) throw new Error('cannot find wasmFD')


      //
      // console.log('fd_read: awaiting wasmFD.socket.fd_read');
      // let data = wasmFD.socket.fd_read();
      wasmFD.socket.fd_read();
      // console.log('fd_read: wasmFD.socket.fd_read returned [%o]', data);

      HEAP32[pnum >> 2] = 0;
      return 0;

    }
  },


  /**
   * _fd_write
   * 
   *  Let's intercept this so that ...
   * 
   * @param {*} fd 
   * @param {*} iov 
   * @param {*} iovcnt 
   * @param {*} pnum 
   * @returns 
   */
  fd_write: function(fd, iov, iovcnt, pnum) {

    if (fd < 10) {  // If not a ziti-browzer-core ZitiChannel fd
      var num = 0;
      for (var i = 0; i < iovcnt; i++) {
        var ptr = HEAP32[iov >> 2];
        var len = HEAP32[iov + 4 >> 2];
        iov += 8;
        for (var j = 0; j < len; j++) {
          // SYSCALLS.printChar(fd, HEAPU8[ptr + j]);
          printChar(fd, HEAPU8[ptr + j]);
        }
        num += len;
      }
      HEAP32[pnum >> 2] = num;
      return 0;  
    }

    else {  // OK, we've got a ziti-browzer-core ZitiChannel fd, so find the associated ZitiChannel

      const wasmFD = _zitiContext._wasmFDsById.get( fd );
      if (wasmFD === null) throw new Error('cannot find wasmFD')

      // console.log("js-library:fd_write(): entered for fd: ", fd);

      // convert WASM memory to JS Buffer so we can send it

      var num = 0;
      for (var i = 0; i < iovcnt; i++) {
        var ptr = HEAP32[iov >> 2];
        var len = HEAP32[iov + 4 >> 2];
        iov += 8;

        // Form an array that maps the WASM memory so we can pass it to the JS run time
        var array = new Uint8Array(Module.HEAPU8.buffer, ptr, len);

        wasmFD.socket.fd_write(array);

        num += len;
      }

      HEAP32[pnum >> 2] = num;
      
      return 0;
    }

  }


});

