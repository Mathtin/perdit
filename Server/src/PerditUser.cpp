#include "PerditUser.h"

PerditUser::PerditUser(Socket *sock, LPSOCKADDR_IN local, LPSOCKADDR_IN remote)
    : userSock(sock), localaddr(local), remoteaddr(remote) {
    status = UserStatusUnknown;
}

PerditUser::~PerditUser() {
    delete userSock;
}

UserStatus PerditUser::Status() {
    return status;
}
