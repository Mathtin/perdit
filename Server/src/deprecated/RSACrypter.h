#ifndef RSACrypter_H
#define RSACrypter_H

#include <vector>
#include <map>
#include <cstdint>
// Crypto++ Headers
#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>

using namespace CryptoPP;

class RSACrypter {
  public:
    RSACrypter(RSA::PrivateKey priv, RSA::PublicKey pub);
    RSACrypter();
    ~RSACrypter();

    uint32_t BlockSize();

    CryptWithPrivateKey();

  private:
    RSA::PrivateKey PrivKey;
    RSA::PublicKey PubKey;
    uint32_t blockSize;
};

class RSAEncrypter : RSACrypter {
  public:
    // SignBlock(char* )
};

#endif // !RSACrypter_H
