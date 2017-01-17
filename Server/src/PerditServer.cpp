#include <iostream>
#include <set>
#include <vector>
#include <thread>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include "Socket.h"
#include "RSAKeyManager.h"
#include "PackageManager.h"

using namespace std;

#define PUBSERVKEY "rsaserverpub.txt"
#define PRIVSERVKEY "rsaserverpriv.txt"
#define PUBUSERKEY "rsauserpub.txt"
#define PRIVUSERKEY "rsauserpriv.txt"

struct PreServer {
    PreServer() : olds(0) {}
    RSAKeyManager km;
    PackageManager pm;
    LPListeningSocket sock;
    set<LPSocket> ss;
    vector<LPSocket> olds;
};

typedef PreServer *LPPreServer;

void Connected(LPVOID lp, LPSocket sock, LPSOCKADDR_IN local);

void Disconnected(LPVOID lp, LPSocket sock, int error);

int main(int argc, char *argv[]) {
    PreServer pserv;
    pserv.km.Load(PUBSERVKEY, PRIVSERVKEY, 0);
    pserv.km.Load(PUBUSERKEY, NULL, 1);
    cout << " [*] Starting Perdit Server" << endl;
    pserv.sock = new ListeningSocket("6767");
    pserv.sock->StartAccepting(&Connected, &pserv);
    cout << " [*] Perdit Server Started" << endl;
    auto handle = thread([&pserv]() {
        char Buffer[PACKSIZE];
        Package *p;
        uint32_t lastOpSo = Socket::OpenedSockets();
        while (true) {
            if (lastOpSo != Socket::OpenedSockets()) {
                lastOpSo = Socket::OpenedSockets();
                cout << " [ ] Opened sockets: " << lastOpSo << endl;
            }
            pserv.pm.WaitForPackages();
            for (auto i : pserv.olds) {
                delete i;
            }
            pserv.olds.clear();
            if (!pserv.pm.Recieving()) {
                return;
            }
            p = pserv.pm.Pop();
            int res1 = 0, res2 = 0;
            PackageType ptype = p->Type();
            if (ptype == SignedPackage) {
                res1 = p->Verify(pserv.km.GetPublicKey(1));
                res2 = p->Decrypt(pserv.km.GetPrivateKey(0));
            } else if (ptype == EncryptedPackage) {
                res2 = p->Decrypt(pserv.km.GetPrivateKey(0));
            }
            cout << " [ ] (" << p->UserID() << ')';
            if (ptype == EncryptedPackage) {
                cout << "-";
            } else if (ptype == SignedPackage) {
                cout << "#";
            }
            if (res1 || res2) {
                cout << "Bad package! Passing.." << endl;
                delete p;
                continue;
            }
            p->Read((byte *)Buffer, PACKSIZE);
            delete p;
            Buffer[PACKSIZE - 1] = 0;
            cout << '>' << Buffer << '<' << endl;
        }
    });
    char Buffer[PACKSIZE];
    Package *p;
    int num;
    LPSocket cl;
    while (cin >> Buffer) {
        if (strcmp(Buffer, "exit") == 0) {
            pserv.pm.StopRecieve();
            pserv.sock->StopAccepting();
            break;
        }
        num = atoi(Buffer);
        cin >> Buffer;
        if (num == 0) {
            continue;
        }
        cl = NULL;
        for (auto i = pserv.ss.begin(); i != pserv.ss.end(); i++, num--) {
            if (num == 1) {
                cl = (*i);
                break;
            }
        }
        if (!cl) {
            continue;
        }
        p = new Package(0, 0);
        p->Write((byte *)Buffer, PACKDATASIZE);
        p->Encrypt(pserv.km.GetPublicKey(1));
        p->Sign(pserv.km.GetPrivateKey(0));
        p->Send(cl);
        delete p;
    }
    handle.join();
    delete pserv.sock;
    return 0;
}

void Connected(LPVOID lp, LPSocket sock, LPSOCKADDR_IN local) {
    LPPreServer pserv = (LPPreServer)lp;
    struct in_addr addr = sock->Addr();
    cout << " [!] Connected from: " << (uint)addr.S_un.S_un_b.s_b1 << '.'
         << (uint)addr.S_un.S_un_b.s_b2 << '.' << (uint)addr.S_un.S_un_b.s_b3
         << '.' << (uint)addr.S_un.S_un_b.s_b4 << endl;
    cout << " [ ] Opened sockets: " << Socket::OpenedSockets() << endl;
    pserv->ss.insert(sock);
    pserv->pm.RecieveFrom(sock, &Disconnected, pserv);
}

void Disconnected(LPVOID lp, LPSocket sock, int error) {
    LPPreServer pserv = (LPPreServer)lp;
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
    pserv->olds.push_back(*pserv->ss.find(sock));
    pserv->ss.erase(sock);
}
