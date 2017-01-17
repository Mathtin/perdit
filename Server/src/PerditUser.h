#ifndef PerditUser_H
#define PerditUser_H

#include <cstdint>
#include "Socket.h"
#include <rsa.h>

using namespace CryptoPP;

enum UserStatus { UserStatusUnknown = 1, UserAwaitHandshake, UserStatusOnline };

class PerditUser {
  public:
    PerditUser(Socket *sock, LPSOCKADDR_IN local, LPSOCKADDR_IN remote);
    ~PerditUser();

    UserStatus Status();

  private:
    uint64_t id;
    Socket *userSock;
    LPSOCKADDR_IN localaddr, remoteaddr;
    UserStatus status;
    RSA::PublicKey key;
};

#endif // !SocketManager_H
