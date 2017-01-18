#ifndef PerditUser_H
#define PerditUser_H

#include <cstdint>
#include <Socket.h>
#include <PackageManager.h>
#include <rsa.h>

using namespace CryptoPP;

class PerditUser;
typedef PerditUser *LPPerditUser;

enum UserStatus { UserStatusUnknown = 1, UserAwaitHandshake, UserStatusOnline };

class PerditUser {
  public:
    PerditUser(Socket *sock, uint64_t uid, LPSOCKADDR_IN local);
    ~PerditUser();

    UserStatus Status();
    uint64_t ID();
    void Send(LPPackage p);
    void SetPublicKey(RSA::PublicKey &k);
    RSA::PublicKey &GetPublicKey();

  private:
    uint64_t id;
    Socket *userSock;
    LPSOCKADDR_IN localaddr;
    UserStatus status;
    RSA::PublicKey key;
};

#endif // !PerditUser_H
