
import {LibCrypto} from "../dist/esm/index.js";

describe("public key and address from private key", function () {
  this.timeout(500);

  beforeEach(async function () {
    this.libCrypto = new LibCrypto();
    await this.libCrypto.initialize();
  });

  it("generates an EC keypair", async function () {
    let { libCrypto } = this;
    
    let pkey = libCrypto.generateECKey({});

    let privateKeyPEM = libCrypto.getPrivateKeyPEM(pkey)
    console.log(privateKeyPEM);
    expect(privateKeyPEM).to.not.equal(undefined);
    expect(privateKeyPEM.startsWith('-----BEGIN PRIVATE KEY-----\n')).to.be.true;
    expect(privateKeyPEM.endsWith('-----END PRIVATE KEY-----\n')).to.be.true;

    let publicKeyPEM = libCrypto.getPublicKeyPEM(pkey);
    console.log(publicKeyPEM);
    expect(publicKeyPEM).to.not.equal(undefined);
    expect(publicKeyPEM.startsWith('-----BEGIN PUBLIC KEY-----\n')).to.be.true;
    expect(publicKeyPEM.endsWith('-----END PUBLIC KEY-----\n')).to.be.true;
  
  });

  it("generates a CSR", async function () {
    let { libCrypto } = this;
    
    let pkey = libCrypto.generateECKey({});

    let privateKeyPEM = libCrypto.getPrivateKeyPEM(pkey)
    console.log(privateKeyPEM);
    expect(privateKeyPEM).to.not.equal(undefined);
    expect(privateKeyPEM.startsWith('-----BEGIN PRIVATE KEY-----\n')).to.be.true;
    expect(privateKeyPEM.endsWith('-----END PRIVATE KEY-----\n')).to.be.true;

    let csr = libCrypto.createCertificateSigningRequest({
      key: pkey,
    })
    console.log(csr);
    expect(csr).to.not.equal(undefined);
    expect(csr.startsWith('-----BEGIN CERTIFICATE REQUEST-----\n')).to.be.true;
    expect(csr.endsWith('-----END CERTIFICATE REQUEST-----\n')).to.be.true;  
  });

  
});
