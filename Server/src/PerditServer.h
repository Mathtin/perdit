#ifndef PerditServer_H
#define PerditServer_H

#include "Socket.h"
#include <map>
#include <stack>
#include <cstdint>
#include <RSAKeyManager.h>
#include <PackageManager.h>
#include "PerditUser.h"

using namespace CryptoPP;
class PerditServer;
typedef PerditServer *LPPerditServer;

enum {
    CTRLHandshake = 1,
    CTRLNewMessage,
    CTRLMessageAccepted,
    CTRLContactList,
    CTRLContactError
};

class PerditServer {
  public:
    PerditServer(const char *sPort, const char *PrivateKeyFile,
                 const char *PublicKeyFile);
    ~PerditServer();
    void Stop();
    std::map<uint64_t, LPPerditUser> &Users();
    bool Active();
    int Send(const char *data, size_t size, uint64_t uid, bool encrypt);
    int Send(const char *data, size_t size, LPPerditUser user, bool encrypt);

  private:
    bool bActive;
    uint64_t PackagesSended;
    RSAKeyManager km;
    PackageManager pm;
    LPListeningSocket sock;
    std::map<uint64_t, LPPerditUser> users;
    std::stack<LPPerditUser> oldusers;
    HANDLE hPackageProcessRoutine;
    DWORD WINAPI PackageProcessRoutine();
    // Static Members
    static void OnConnection(LPVOID lp, LPSocket sock, LPSOCKADDR_IN local);
    static void OnDisconnection(LPVOID lp, LPSocket sock, int error);
};

#endif // !PerditServer_H
