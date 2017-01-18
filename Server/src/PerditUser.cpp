#include "PerditUser.h"

PerditUser::PerditUser(Socket *sock, uint64_t uid, LPSOCKADDR_IN local)
    : id(uid), userSock(sock), localaddr(local) {
    status = UserAwaitHandshake;
}

PerditUser::~PerditUser() {
    delete userSock;
    // delete localaddr;
}

UserStatus PerditUser::Status() {
    return status;
}

uint64_t PerditUser::ID() {
    return id;
}

void PerditUser::Send(LPPackage p) {
    p->Send(userSock);
}

RSA::PublicKey &PerditUser::GetPublicKey() {
    return key;
}

void PerditUser::SetPublicKey(RSA::PublicKey &k) {
    key = k;
    if (status == UserAwaitHandshake) {
        status = UserStatusOnline;
    }
}
