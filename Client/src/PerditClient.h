#ifndef PerditClient_H
#define PerditClient_H

#include <vector>
#include <map>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <Socket.h>
#include <RSAKeyManager.h>
#include <PackageManager.h>

class PerditClient;
typedef PerditClient *LPPerditClient;

enum {
    CTRLHandshake = 1,
    CTRLSeveralPackages,
    CTRLNewMessage,
    CTRLMessageAccepted,
    CTRLContactList,
    CTRLContactError
};
static const size_t MAXNAMELEN = 32;

struct Contact {
    char Nickname[MAXNAMELEN];
    uint64_t UserID;
};

class PerditClient {
  public:
    PerditClient(const char *sIP, const char *sPort, const char *PrivateKeyFile,
                 const char *PublicKeyFile, const char *nick);
    ~PerditClient();
    bool Active();
    bool Connected();
    void Connect();
    void Disconnect();

    uint64_t ID();
    void SetNickname(const char *nick);
    const char *GetNickname();

    void Send(const byte *data, size_t size);

  private:
    RSAKeyManager km;
    PackageManager pm;
    LPConnectingSocket sock;
    uint64_t id;
    RSA::PublicKey ServKey;
    bool HandShaked;
    uint64_t PackagesSended;
    char NickName[MAXNAMELEN];
    HANDLE hPackageProcessRoutine;
    std::vector<Contact> ContactList;
    DWORD WINAPI PackageProcessRoutine();
    void SendHandshake(uint64_t userIDN);
    // Static Members
    static void OnDisconnection(LPVOID lp, LPSocket sock, int error);
};

#endif // !PerditClient_H
