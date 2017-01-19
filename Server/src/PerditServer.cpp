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
    hTaskProcessRoutine = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)&TaskProcessRoutine, this, 0, NULL);
    if (hTaskProcessRoutine == INVALID_HANDLE_VALUE) {
        fprintf(stderr, " [x] TaskProcessRoutine thread failed to create: %lu",
                GetLastError());
        return;
    }
    bActive = true;
}

PerditServer::~PerditServer() {
    pm.StopRecieve();
    if (bActive) {
        bActive = false;
        cv.notify_all();
        WaitForSingleObject(hPackageProcessRoutine, INFINITE);
        CloseHandle(hPackageProcessRoutine);
        WaitForSingleObject(hTaskProcessRoutine, INFINITE);
        CloseHandle(hTaskProcessRoutine);
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
    // std::lock_guard<std::mutex> lock(mtx);
    pm.StopRecieve();
    if (bActive) {
        bActive = false;
        cv.notify_all();
        WaitForSingleObject(hPackageProcessRoutine, INFINITE);
        CloseHandle(hPackageProcessRoutine);
        WaitForSingleObject(hTaskProcessRoutine, INFINITE);
        CloseHandle(hTaskProcessRoutine);
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
}

std::map<uint64_t, LPPerditUser> &PerditServer::Users() {
    return users;
}

bool PerditServer::Active() {
    // std::lock_guard<std::mutex> lock(mtx);
    return bActive;
}

void PerditServer::SendMessageFor(uint64_t uid, uint64_t from, byte *msg,
                                  size_t msgsize) {
    pendingTasks.push(new Task(CTRLNewMessage, msg, msgsize, from, uid));
    cv.notify_all();
}

void PerditServer::SendContactList(uint64_t uid) {
    pendingTasks.push(new Task(CTRLContactList, nullptr, 0, 0, uid));
    cv.notify_all();
}

void PerditServer::SendMessageFor(LPPerditUser user, uint64_t from, byte *msg,
                                  size_t msgsize) {
    Package p(0, PackagesSended);
    byte ctrl = CTRLNewMessage, mmsg = msgsize;
    from = htonll(from);
    p.Write(&ctrl, 1);
    p.Write((byte *)&from, 8);
    p.Write(&mmsg, 1);
    p.Write(msg, mmsg);
    p.Encrypt(user->GetPublicKey());
    p.Sign(km.GetPrivateKey());
    user->Send(&p);
    PackagesSended++;
}

int PerditServer::Send(const char *data, size_t size, uint64_t uid,
                       bool encrypt) {
    // std::lock_guard<std::mutex> lock(mtx);
    auto u = users.find(uid);
    if (u == users.end()) {
        return 1;
    }
    LPPerditUser user = u->second;
    if (user->Status() == UserAwaitHandshake ||
        user->Status() == UserStatusUnknown) {
        return 0;
    }
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
    // std::lock_guard<std::mutex> lock(mtx);
    if (user->Status() == UserAwaitHandshake ||
        user->Status() == UserStatusUnknown) {
        return 0;
    }
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
                for (auto u : users) {
                    SendContactList(u.second->ID());
                }
            }
            delete p;
            continue;
        } else {
            delete p;
            continue;
        }
        if (res1 || res2) {
            printf("Bad package! Passing..\n");
            delete p;
            continue;
        }
        p->Read(Buffer, 1);
        size_t parts = 1;
        if (Buffer[0] == CTRLSeveralPackages) {
            p->Read(Buffer, 1);
            parts = Buffer[0];
        }
        for (size_t i = 0; i < parts; i++) {
            switch (Buffer[0]) {
            case CTRLNewMessage: {
                p->Read(Buffer, 8);
                uint64_t idfor = ntohll(*(uint64_t *)Buffer);
                p->Read(Buffer, 1);
                size_t msize = Buffer[0];
                p->Read(Buffer, msize);
                Buffer[msize] = '\0';
                SendMessageFor(idfor, p->UserID(), Buffer, msize);
                break;
            }
            case CTRLContactList: {
                SendContactList(p->UserID());
                break;
            }
            default:
                i = parts;
                break;
            }
        }
        delete p;
    }
    return 0;
}

DWORD WINAPI PerditServer::TaskProcessRoutine() {
    Task *t;
    LPPackage p;
    while (bActive) {
        std::unique_lock<std::mutex> lck(mtx);
        cv.wait(lck);
        while (pendingTasks.size()) {
            t = pendingTasks.top();
            pendingTasks.pop();
            switch (t->type) {
            case CTRLNewMessage: {
                auto u = users.find(t->IDFor);
                byte ctrl;
                uint64_t sid;
                if (u == users.end()) {
                    u = users.find(t->IDFrom);
                    if (u == users.end()) {
                        break;
                    }
                    ctrl = CTRLContactError;
                    sid = htonll(t->IDFrom);
                    p = new Package(0, PackagesSended);
                    p->Write(&ctrl, 1);
                    p->Write((byte *)&sid, 8);
                    p->Encrypt(u->second->GetPublicKey());
                    p->Sign(km.GetPrivateKey());
                    u->second->Send(p);
                    delete p;
                    PackagesSended++;
                    break;
                }
                ctrl = CTRLNewMessage;
                sid = htonll(t->IDFrom);
                p = new Package(0, PackagesSended);
                p->Write(&ctrl, 1);
                p->Write((byte *)&sid, 8);
                ctrl = t->BufferSize;
                p->Write(&ctrl, 1);
                p->Write(t->Buffer, ctrl);
                p->Encrypt(u->second->GetPublicKey());
                p->Sign(km.GetPrivateKey());
                u->second->Send(p);
                delete p;
                PackagesSended++;
                break;
            }
            case CTRLContactList: {
                auto ui = users.find(t->IDFor);
                if (ui == users.end()) {
                    break;
                }
                int i = 0;
                size_t pending = users.size();
                uint64_t cuid;
                byte part = (pending > 8 ? 8 : pending),
                     ctrl = CTRLSeveralPackages;
                p = new Package(0, PackagesSended);
                if (pending < 8) {
                    p->Write(&ctrl, 1);
                    ctrl = 2;
                    p->Write(&ctrl, 1);
                }
                ctrl = CTRLContactList;
                p->Write(&ctrl, 1);
                if (part)
                    p->Write(&part, 1);
                for (auto u : users) {
                    cuid = htonll(u.second->ID());
                    p->Write((byte *)&cuid, 8);
                    p->Write((byte *)u.second->GetNickname(), MAXNAMELEN);
                    i = (i + 1) % 8;
                    pending--;
                    if (i == 0) {
                        part = (pending > 8 ? 8 : pending);
                        p->Encrypt(ui->second->GetPublicKey());
                        p->Sign(km.GetPrivateKey());
                        ui->second->Send(p);
                        PackagesSended++;
                        delete p;
                        p = new Package(0, PackagesSended);
                        if (part) {
                            if (pending < 8) {
                                ctrl = CTRLSeveralPackages;
                                p->Write(&ctrl, 1);
                                ctrl = 2;
                                p->Write(&ctrl, 1);
                            }
                            ctrl = CTRLContactList;
                            p->Write(&ctrl, 1);
                            p->Write(&part, 1);
                        }
                    }
                }
                ctrl = CTRLContactListEnd;
                p->Write(&ctrl, 1);
                p->Encrypt(ui->second->GetPublicKey());
                p->Sign(km.GetPrivateKey());
                ui->second->Send(p);
                PackagesSended++;
                delete p;
                break;
            }
            }
            delete t;
        }
    }
    return 0;
}

void PerditServer::OnConnection(LPVOID lp, LPSocket sock, LPSOCKADDR_IN local) {
    LPPerditServer serv = (LPPerditServer)lp;
    // std::lock_guard<std::mutex> lock(serv->mtx);
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
    LPPerditUser user = serv->users[sock->SocketID()];
    // std::lock_guard<std::mutex> lock(serv->mtx);
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
        printf(" [ ] %s disconnected (%u.%u.%u.%u)\n", user->GetNickname(),
               ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
    }
    printf(" [ ] Opened sockets: %lu\n", Socket::OpenedSockets());
    serv->oldusers.push(user);
    serv->users.erase(sock->SocketID());
    for (auto u : serv->users) {
        serv->SendContactList(u.second->ID());
    }
}
