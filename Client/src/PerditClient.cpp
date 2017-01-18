#include "PerditClient.h"

PerditClient::PerditClient(const char *sIP, const char *sPort,
                           const char *PrivateKeyFile,
                           const char *PublicKeyFile, const char *nick) {
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
        p->Read(Buffer, PACKSIZE);
        delete p;
        Buffer[PACKSIZE - 1] = 0;
        printf(">%s<\n", Buffer);
        continue;
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
    printf("Type anything to reconnect or \"exit\" to close client:");
}