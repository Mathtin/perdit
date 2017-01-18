#ifndef RSAKeyManager_H
#define RSAKeyManager_H

#include <cstdint>
// Crypto++ Headers
#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>

using namespace CryptoPP;

static const uint32_t RSAKeySizeBits = 1024;
static const uint32_t RSAKeySizeBytes = RSAKeySizeBits >> 3;

enum { RSAKEY_SAVE_FAILED = 1, RSAKEY_NOT_FOUND };

class RSAKeyManager {
  public:
    RSAKeyManager();
    ~RSAKeyManager();

    int NewKey();
    int Load(const char *pubKeyFile, const char *privKeyFile);
    int Save(const char *pubKeyFile, const char *privKeyFile);
    RSA::PublicKey &GetPublicKey();
    RSA::PrivateKey &GetPrivateKey();
    const byte *GetPublicKeyBin(size_t &size);

  private:
    RSA::PublicKey pkey;
    RSA::PrivateKey prkey;
    ByteQueue PublicKeyBin;
};

#endif // !RSAKeyManager_H
