#ifndef RSAKeyManager_H
#define RSAKeyManager_H

#include <vector>
#include <map>
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

    int NewKey(uint64_t id);
    int Load(const char *pubKeyFile, const char *privKeyFile, uint64_t id);
    int Save(const char *pubKeyFile, const char *privKeyFile, uint64_t id);
    int Delete(uint64_t id);
    RSA::PublicKey &GetPublicKey(uint64_t id);
    RSA::PrivateKey &GetPrivateKey(uint64_t id);
    std::pair<RSA::PrivateKey *, RSA::PublicKey *> &operator[](uint64_t id);

  private:
    std::map<uint64_t, std::pair<RSA::PrivateKey *, RSA::PublicKey *>> keys;
};

#endif // !RSAKeyManager_H
