#include "PerditClient.h"

PerditClient::PerditClient(const char *sIP, const char *sPort,
                           const char *PrivateKeyFile,
                           const char *PublicKeyFile, const char *nick) {
    startedRecievingContactsList = false;
    HandShaked = false;
    PackagesSended = 0;
    km.Load(PublicKeyFile, PrivateKeyFile);
    memcpy(NickName, nick, MAXNAMELEN);
    NickName[MAXNAMELEN - 1] = '\0';
    sock = new ConnectingSocket(sIP, sPort);
    if (!sock->Connected()) {
        return;
    }
    hPackageProcessRoutine = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)&PackageProcessRoutine, this, 0, NULL);
    if (hPackageProcessRoutine == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "PackageProcessRoutine thread failed to create: %lu",
                GetLastError());
        return;
    }
    pm.RecieveFrom(sock, &PerditClient::OnDisconnection, this);
}

PerditClient::~PerditClient() {
    for (auto i : ContactList) {
        delete i;
    }
    pm.StopRecieve();
    if (Active()) {
        WaitForSingleObject(hPackageProcessRoutine, INFINITE);
        CloseHandle(hPackageProcessRoutine);
    }
    sock->Disconnect();
    delete sock;
}

uint64_t PerditClient::ID() {
    return id;
}

bool PerditClient::Active() {
    return HandShaked;
}

bool PerditClient::Connected() {
    if (!sock->Connected()) {
        HandShaked = false;
    }
    return sock->Connected();
}

void PerditClient::Connect() {
    sock->Connect();
    if (!Connected()) {
        return;
    }
    if (!sock->Recieving()) {
        pm.RecieveFrom(sock, &PerditClient::OnDisconnection, this);
        hPackageProcessRoutine = CreateThread(
            NULL, 0, (LPTHREAD_START_ROUTINE)&PackageProcessRoutine, this, 0,
            NULL);
        if (hPackageProcessRoutine == INVALID_HANDLE_VALUE) {
            fprintf(stderr,
                    "PackageProcessRoutine thread failed to create: %lu",
                    GetLastError());
            return;
        }
    }
}

void PerditClient::Disconnect() {
    pm.StopRecieve();
    if (Active()) {
        WaitForSingleObject(hPackageProcessRoutine, INFINITE);
        CloseHandle(hPackageProcessRoutine);
    }
    sock->Disconnect();
    HandShaked = false;
}

void PerditClient::SetNickname(const char *nick) {
    memcpy(NickName, nick, MAXNAMELEN);
    NickName[MAXNAMELEN - 1] = '\0';
}

const char *PerditClient::GetNickname() {
    return NickName;
}

const std::vector<Contact *> &PerditClient::GetContactList() {
    return ContactList;
}

void PerditClient::Send(const byte *data, size_t size) {
    if (!Active()) {
        return;
    }
    Package p(id, PackagesSended);
    p.Write(data, size);
    p.Encrypt(ServKey);
    p.Sign(km.GetPrivateKey());
    p.Send(sock);
    PackagesSended++;
}

void PerditClient::SendHandshake(uint64_t userIDN) {
    Package phand(1, PackagesSended);
    byte CTRL = CTRLHandshake, bkeysize;
    size_t keysize;
    const byte *binkey = km.GetPublicKeyBin(keysize);
    bkeysize = keysize;
    phand.Write(&CTRL, 1);
    phand.Write((byte *)&userIDN, sizeof(uint64_t));
    phand.Write(&bkeysize, 1);
    phand.Write(binkey, keysize);
    phand.Write((byte *)NickName, MAXNAMELEN);
    phand.Send(sock);
}

void PerditClient::AskForContactList() {
    Package phand(1, PackagesSended);
    byte CTRL = CTRLContactList;
    phand.Write(&CTRL, 1);
    phand.Encrypt(ServKey);
    phand.Sign(km.GetPrivateKey());
    phand.Send(sock);
    PackagesSended++;
}

const char *PerditClient::NickNameByUID(uint64_t uid) {
    for (auto i : ContactList) {
        if (i->UserID == uid) {
            return i->Nickname;
        }
    }
    return nullptr;
}

uint64_t PerditClient::UIDByNickname(const char *nick) {
    size_t j;
    for (auto i : ContactList) {
        for (j = 0; j < MAXNAMELEN; j++) {
            if (i->Nickname[j] != nick[j]) {
                break;
            } else if (!nick[j]) {
                return i->UserID;
            }
        }
        if (j == MAXNAMELEN) {
            return i->UserID;
        }
    }
    return 0;
}

int PerditClient::SendMessage(const char *msg, size_t size, const char *nick) {
    if (!HandShaked) {
        return 1;
    }
    uint64_t uid = htonll(UIDByNickname(nick));
    if (!uid) {
        return 1;
    }
    Package p(id, PackagesSended);
    byte ctrl = CTRLNewMessage;
    p.Write(&ctrl, 1);
    p.Write((byte *)&uid, 8);
    ctrl = size;
    p.Write(&ctrl, 1);
    p.Write((byte *)msg, ctrl);
    p.Encrypt(ServKey);
    p.Sign(km.GetPrivateKey());
    p.Send(sock);
    PackagesSended++;
    return 0;
}

DWORD WINAPI PerditClient::PackageProcessRoutine() {
    byte Buffer[PACKDATASIZE];
    Package *p;
    while (true) {
        pm.WaitForPackages();
        if (!pm.Recieving()) {
            return 0;
        }
        p = pm.Pop();
        int res1 = 0, res2 = 0;
        PackageType ptype = p->Type();
        if (ptype == SignedPackage) {
            res1 = p->Verify(ServKey);
            res2 = p->Decrypt(km.GetPrivateKey());
        } else if (ptype == EncryptedPackage) {
            res2 = p->Decrypt(km.GetPrivateKey());
        } else if (ptype == OpenPackage) {
            p->Read((byte *)Buffer, PACKDATASIZE);
            if (Buffer[0] == CTRLHandshake) {
                uint64_t userID = ntohll(*(uint64_t *)(Buffer + 1));
                id = userID;
                ByteQueue bytes;
                bytes.Put(Buffer + 2 + sizeof(uint64_t),
                          (size_t)Buffer[1 + sizeof(uint64_t)]);
                bytes.MessageEnd();
                ServKey.Load(bytes);
                HandShaked = true;
                uint64_t userIDN = htonll(userID);
                SendHandshake(userIDN);
                PackagesSended++;
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
            p->Read(Buffer, 1);
        }
        for (size_t i = 0; i < parts; i++) {
            switch (Buffer[0]) {
            case CTRLNewMessage: {
                p->Read(Buffer, 8);
                uint64_t from = ntohll(*(uint64_t *)Buffer);
                auto nick = (from ? NickNameByUID(from) : "Server");
                p->Read(Buffer, 1);
                size_t msize = Buffer[0];
                p->Read(Buffer, msize);
                Buffer[msize] = '\0';
                if (!nick) {
                    AskForContactList();
                    printf("[?]:%s\n", Buffer);
                }
                printf("%s:%s\n", nick, Buffer);
                break;
            }
            case CTRLMessageAccepted: {
                p->Read(Buffer, 8);
                uint64_t which = ntohll(*(uint64_t *)Buffer);
                // WHICH???????
                printf("Message Accepted [%llu]\n", which);
                break;
            }
            case CTRLContactError: {
                p->Read(Buffer, 8);
                uint64_t from = ntohll(*(uint64_t *)Buffer);
                auto nick = NickNameByUID(from);
                if (!nick) {
                    AskForContactList();
                    printf("Error: no such user. Disconnected?\n");
                }
                printf("Error: no such user: %s. Disconnected?\n", nick);
                AskForContactList();
                break;
            }
            case CTRLContactList: {
                if (!startedRecievingContactsList) {
                    for (auto c : ContactList) {
                        delete c;
                    }
                    ContactList.clear();
                    startedRecievingContactsList = true;
                }
                p->Read(Buffer, 1);
                uint64_t amount = Buffer[0], id;
                for (size_t c = 0; c < amount; c++) {
                    p->Read(Buffer, 8);
                    id = ntohll(*(uint64_t *)Buffer);
                    p->Read(Buffer, MAXNAMELEN);
                    ContactList.push_back(new Contact((char *)Buffer, id));
                }
                break;
            }
            case CTRLContactListEnd: {
                startedRecievingContactsList = false;
                break;
            }
            default:
                i = parts;
                break;
            }
            p->Read(Buffer, 1);
        }
        delete p;
    }
}

void PerditClient::OnDisconnection(LPVOID lp, LPSocket sock, int error) {
    LPPerditClient client = (LPPerditClient)lp;
    client->pm.StopRecieve();
    WaitForSingleObject(client->hPackageProcessRoutine, INFINITE);
    CloseHandle(client->hPackageProcessRoutine);
    client->HandShaked = false;
    uint16_t ipaddr[4] = {
        sock->Addr().S_un.S_un_b.s_b1, sock->Addr().S_un.S_un_b.s_b2,
        sock->Addr().S_un.S_un_b.s_b3, sock->Addr().S_un.S_un_b.s_b4};
    if (error == WSAECONNRESET) {
        printf("Server reset connection (%u.%u.%u.%u)\n", ipaddr[0], ipaddr[1],
               ipaddr[2], ipaddr[3]);
    } else if (error) {
        fprintf(stderr, "WSAGetOverlappedResult() failed with error %d\n",
                error);
    } else {
        printf("Server went offline (%u.%u.%u.%u)\n", ipaddr[0], ipaddr[1],
               ipaddr[2], ipaddr[3]);
    }
    printf("Type anything to reconnect or \"\\exit\" to close client:");
}