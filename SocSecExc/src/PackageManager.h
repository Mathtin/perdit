#ifndef PackageManager_H
#define PackageManager_H

#include <queue>
#include <mutex>
#include <cstdint>
#include "Socket.h"
#include "RSAKeyManager.h"

enum PackageType {
    OpenPackage = 0,
    EncryptedPackage,
    SignedPackage,
    InvalidPackage
};

enum {
    PackageEncrypted = 0,
    PackageSigned = 0,
    PackageDecrypted = 0,
    ErrorPackageOpened,
    ErrorPackageSigned,
    ErrorPackageEncrypted,
    ErrorPackageInvalid
};

const uint32_t PACKSIZE =
    (1 << 7) * 3 + RSAKeySizeBytes + 1; // Base + Signature
const uint32_t PACKSALTSIZE = 12;
const uint32_t PACKBLOCKSIZE = RSAKeySizeBytes - PACKSALTSIZE;
const uint32_t PACKFIRSTBLOCKSIZE = PACKBLOCKSIZE - sizeof(uint64_t) * 2;
const uint32_t PACKDATASIZE = PACKFIRSTBLOCKSIZE + PACKBLOCKSIZE * 2;

const byte PACKSIGNED = (1 << 0);
const byte PACKENCRYPTED = (1 << 1);
const byte PACKOPEN = 0;

class Package;
class PackageManager;

typedef Package *LPPackage;
typedef PackageManager *LPPackageManager;

class PackageManager {
  public:
    PackageManager();
    ~PackageManager();

    void Push(LPPackage p);
    LPPackage Pop(void);

    void WaitForPackages();
    bool PackagesAvailable();
    size_t NumPackagesAvailable();

    bool Recieving();
    void StopRecieve();
    void ContinueRecieve();

    int RecieveFrom(LPSocket, DiscSocketFunc, LPVOID arg);
    byte *GetBuffer();

    static const size_t BufferSize;

  protected:
    bool bStoppedRecv;
    std::queue<LPPackage> q;
    byte Buffer[PACKSIZE << 4];
    std::mutex mtx;
    HANDLE hNewPackage;
    uint64_t PackagesRecieved;
    // Static members
    static void SocketReciever(LPVOID pm, Socket *s, size_t Recieved);
};

class Package {
    friend PackageManager;

  public:
    Package(uint64_t uid, uint64_t paid);
    uint32_t Write(const byte *data, uint32_t size);
    uint32_t Read(byte *data, uint32_t size);
    void ClearData();
    uint32_t RawRewrite(const byte *data, uint32_t size, bool Signed,
                        bool Encrypted);
    uint32_t WriteSign(const byte *sign);

    int Sign(RSA::PrivateKey key);
    int Encrypt(RSA::PublicKey key);

    int Decrypt(RSA::PrivateKey key);
    int Verify(RSA::PublicKey key);

    void Send(Socket *sock);

    uint64_t UserID();
    uint64_t PackageID();

    uint32_t Size();

    PackageType Type();

  private:
    byte UData[PACKSIZE];
    byte Data[PACKDATASIZE];
    bool placed;
    size_t dbegin, dend;
    uint64_t userid, pacid;
    uint32_t available;
    PackageType type;
};

#endif // !PackageManager_H