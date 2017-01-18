#include "PerditServer.h"

PerditServer::PerditServer(const char *sPort, const char *PrivateKeyFile,
                           const char *PublicKeyFile) {
    PackagesSended = 0;
    bActive = false;
    sock = nullptr;
    km.Load(PublicKeyFile, PrivateKeyFile);
    sock = new ListeningSocket(sPort);
    if (!sock->Listening()) {
        return;
    }
    sock->StartAccepting(&PerditServer::OnConnection, this);
    if (!sock->Accepting()) {
        return;
    }
    hPackageProcessRoutine = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)&PackageProcessRoutine, this, 0, NULL);
    if (hPackageProcessRoutine == INVALID_HANDLE_VALUE) {
        fprintf(stderr,
                " [x] PackageProcessRoutine thread failed to create: %lu",
                GetLastError());
        return;
    }
    bActive = true;
}

PerditServer::~PerditServer() {
    pm.StopRecieve();
    if (bActive) {
        WaitForSingleObject(hPackageProcessRoutine, INFINITE);
        CloseHandle(hPackageProcessRoutine);
        sock->StopAccepting();
    }
    while (oldusers.size()) {
        delete oldusers.top();
        oldusers.pop();
    }
    for (auto i : users) {
        delete i.second;
    }
    delete sock;
}

void PerditServer::Stop() {
    pm.StopRecieve();
    if (bActive) {
        WaitForSingleObject(hPackageProcessRoutine, INFINITE);
        CloseHandle(hPackageProcessRoutine);
        sock->StopAccepting();
    }
    while (oldusers.size()) {
        delete oldusers.top();
        oldusers.pop();
    }
    for (auto i : users) {
        delete i.second;
    }
    users.clear();
    sock->StopAccepting();
    bActive = false;
}

std::map<uint64_t, LPPerditUser> &PerditServer::Users() {
    return users;
}

bool PerditServer::Active() {
    return bActive;
}

int PerditServer::Send(const char *data, size_t size, uint64_t uid,
                       bool encrypt) {
    auto u = users.find(uid);
    if (u == users.end()) {
        return 1;
    }
    LPPerditUser user = u->second;
    Package p(1, PackagesSended);
    p.Write((byte *)data, size);
    if (encrypt) {
        p.Encrypt(user->GetPublicKey());
        p.Sign(km.GetPrivateKey());
    }
    user->Send(&p);
    return 0;
}

int PerditServer::Send(const char *data, size_t size, LPPerditUser user,
                       bool encrypt) {
    Package p(1, PackagesSended);
    p.Write((byte *)data, size);
    if (encrypt) {
        p.Encrypt(user->GetPublicKey());
        p.Sign(km.GetPrivateKey());
    }
    user->Send(&p);
    return 0;
}

DWORD WINAPI PerditServer::PackageProcessRoutine() {
    byte Buffer[PACKSIZE];
    Package *p;
    LPPerditUser user;
    while (true) {
        pm.WaitForPackages();
        while (oldusers.size()) {
            delete oldusers.top();
            oldusers.pop();
        }
        if (!pm.Recieving()) {
            return 0;
        }
        p = pm.Pop();
        auto u = users.find(p->UserID());
        if (u == users.end()) {
            delete p;
            continue;
        } else {
            user = u->second;
        }
        int res1 = 0, res2 = 0;
        PackageType ptype = p->Type();
        if (ptype == SignedPackage) {
            res1 = p->Verify(user->GetPublicKey());
            res2 = p->Decrypt(km.GetPrivateKey());
        } else if (ptype == EncryptedPackage) {
            res2 = p->Decrypt(km.GetPrivateKey());
        } else if (ptype == OpenPackage) {
            p->Read(Buffer, PACKSIZE);
            if (Buffer[0] == CTRLHandshake) {
                uint64_t userID = ntohll(*(uint64_t *)(Buffer + 1));
                if (user->ID() != userID) {
                    printf(" [*] Handshake failed from %llu (dropping)\n",
                           user->ID());
                    delete users[user->ID()];
                    users.erase(user->ID());
                    delete p;
                    continue;
                }
                ByteQueue bytes;
                bytes.Put(Buffer + 2 + sizeof(uint64_t),
                          Buffer[1 + sizeof(uint64_t)]);
                bytes.MessageEnd();
                RSA::PublicKey pubkey;
                pubkey.Load(bytes);
                user->SetPublicKey(pubkey);
                size_t nicknameoff =
                    2 + sizeof(uint64_t) + Buffer[1 + sizeof(uint64_t)];
                user->SetNickname((char *)Buffer + nicknameoff);
                printf(" [*] Handshake from %s\n", user->GetNickname());
            }
            delete p;
            continue;
        } else {
            delete p;
            continue;
        }
        printf(" [ ] (%s)", user->GetNickname());
        if (ptype == EncryptedPackage) {
            printf("-");
        } else if (ptype == SignedPackage) {
            printf("#");
        }
        if (res1 || res2) {
            printf("Bad package! Passing..\n");
            delete p;
            continue;
        }
        p->Read((byte *)Buffer, PACKSIZE);
        delete p;
        Buffer[PACKSIZE - 1] = 0;
        printf(">%s<\n", Buffer);
    }
    return 0;
}

void PerditServer::OnConnection(LPVOID lp, LPSocket sock, LPSOCKADDR_IN local) {
    LPPerditServer serv = (LPPerditServer)lp;
    struct in_addr addr = sock->Addr();
    printf(" [!] Connected from: %u.%u.%u.%u\n", (uint)addr.S_un.S_un_b.s_b1,
           (uint)addr.S_un.S_un_b.s_b2, (uint)addr.S_un.S_un_b.s_b3,
           (uint)addr.S_un.S_un_b.s_b4);
    printf(" [ ] Opened sockets: %lu\n", Socket::OpenedSockets());
    LPPerditUser user = new PerditUser(sock, sock->SocketID(), local);
    serv->users.insert(std::make_pair(user->ID(), user));
    serv->pm.RecieveFrom(sock, &PerditServer::OnDisconnection, serv);
    Package p(1, serv->PackagesSended);
    uint64_t userIDN = htonll(user->ID());
    byte CTRL = CTRLHandshake, bkeysize;
    size_t keysize;
    const byte *binkey = serv->km.GetPublicKeyBin(keysize);
    bkeysize = keysize;
    p.Write(&CTRL, 1);
    p.Write((byte *)&userIDN, sizeof(uint64_t));
    p.Write(&bkeysize, 1);
    p.Write(binkey, keysize);
    user->Send(&p);
    serv->PackagesSended++;
}

void PerditServer::OnDisconnection(LPVOID lp, LPSocket sock, int error) {
    LPPerditServer serv = (LPPerditServer)lp;
    uint16_t ipaddr[4] = {
        sock->Addr().S_un.S_un_b.s_b1, sock->Addr().S_un.S_un_b.s_b2,
        sock->Addr().S_un.S_un_b.s_b3, sock->Addr().S_un.S_un_b.s_b4};
    if (error == WSAECONNRESET) {
        printf(" [!] Connection reset by peer (%u.%u.%u.%u)\n", ipaddr[0],
               ipaddr[1], ipaddr[2], ipaddr[3]);
    } else if (error) {
        fprintf(stderr, " [*] WSAGetOverlappedResult() failed with error %d\n",
                error);
    } else {
        printf(" [ ] Peer disconnected (%u.%u.%u.%u)\n", ipaddr[0], ipaddr[1],
               ipaddr[2], ipaddr[3]);
    }
    printf(" [ ] Opened sockets: %lu\n", Socket::OpenedSockets());
    serv->oldusers.push(serv->users[sock->SocketID()]);
    serv->users.erase(sock->SocketID());
}
