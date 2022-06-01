
import {LibCrypto} from "../dist/esm/index.js";

describe("SSL", function () {

  beforeEach(async function () {
    this.timeout(1000);
    this.libCrypto = new LibCrypto();
    await this.libCrypto.initialize();
  });

  it("generates an SSL Context", async function () {
    let { libCrypto } = this;
    
    let pkey = libCrypto.generateKey({});

    let ctx = libCrypto.ssl_CTX_new();
    console.log(ctx);
    expect(ctx).to.not.equal(undefined);

    ctx = libCrypto.ssl_CTX_add_private_key(ctx, pkey);
    console.log(ctx);
    expect(ctx).to.not.equal(undefined);


    // let ssl = libCrypto.ssl_new(ctx);
    // console.log(ssl);
    // expect(ssl).to.not.equal(undefined);

    let sbio = libCrypto.bio_new_ssl_connect(ctx);
    console.log(sbio);
    expect(sbio).to.not.equal(undefined);

    let ssl = libCrypto.bio_get_ssl(sbio);
    console.log(ssl);
    expect(ssl).to.not.equal(undefined);

    let result = libCrypto.bio_set_conn_hostname(sbio, 'www.google.com:443');
    // let result = libCrypto.bio_set_conn_hostname(sbio, 'ziti-edge-controller:1280');
    console.log(result);
    expect(result).to.equal(1);

    result = libCrypto.bio_do_connect(sbio);
    console.log(result);
    expect(result > 0).to.equal(true);

    // let socket = 1234;
    // let result = libCrypto.ssl_set_fd(ssl, socket);
    // console.log(result);
    // expect(result).to.equal(1);

    // result = libCrypto.ssl_connect(ssl);
    // console.log(result);
    // expect(result).to.equal(1);

  });


  
});
