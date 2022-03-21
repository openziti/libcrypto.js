
import {LibCrypto} from "../dist/esm/index.js";

describe("public key and address from private key", function () {
  this.timeout(500);

  beforeEach(async function () {
    this.libCrypto = new LibCrypto();
    await this.libCrypto.initialize();
  });

  it("generates an EC keypair", async function () {
    let { libCrypto } = this;
    
    let privateKeyPEM = libCrypto.generateECKey({});

    console.log(privateKeyPEM);

    expect(privateKeyPEM).to.not.equal(undefined);
    expect(privateKeyPEM.startsWith('-----BEGIN PRIVATE KEY-----\n')).to.be.true;
    expect(privateKeyPEM.endsWith('-----END PRIVATE KEY-----\n')).to.be.true;

  });

});

