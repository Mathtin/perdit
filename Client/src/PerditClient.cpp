#include <iostream>
#include <cstring>
#include <future>
#include <Socket.h>
#include <RSAKeyManager.h>
#include <PackageManager.h>

using namespace std;

#define PUBSERVKEY "rsaserverpub.txt"
#define PRIVSERVKEY "rsaserverpriv.txt"
#define PUBUSERKEY "rsauserpub.txt"
#define PRIVUSERKEY "rsauserpriv.txt"

struct PreClient {
    RSAKeyManager km;
    PackageManager pm;
    LPConnectingSocket sock;
};

typedef PreClient *LPPreClient;

void Recieved(LPVOID lp, LPPackageManager pm);

void Disconnected(LPVOID lp, LPSocket sock, int error);

int main(int argc, char *argv[]) {
    char Buffer[PACKDATASIZE];
    PreClient pclient;
    pclient.km.Load(PUBSERVKEY, NULL, 0);
    pclient.km.Load(PUBUSERKEY, PRIVUSERKEY, 1);
    Package *p;
    cout << "Connecting..." << endl;
    pclient.sock = new ConnectingSocket("127.0.0.1", "6767");
    while (!pclient.sock->Connected()) {
        cout << "Type anything to reconnect or \"exit\" to close client:";
        cin >> Buffer;
        if (strcmp(Buffer, "exit") == 0) {
            pclient.sock->Disconnect();
            delete pclient.sock;
            return 0;
        }
        pclient.sock->Connect();
    }
    cout << "Connected" << endl;
    pclient.pm.RecieveFrom(pclient.sock, &Disconnected, &pclient);
    auto handle = std::async(std::launch::async, [&pclient]() {
        char Buffer[PACKDATASIZE];
        Package *p;
        while (true) {
            pclient.pm.WaitForPackages();
            if (!pclient.pm.Recieving()) {
                return;
            }
            p = pclient.pm.Pop();
            int res1 = 0, res2 = 0;
            PackageType ptype = p->Type();
            if (ptype == SignedPackage) {
                res1 = p->Verify(pclient.km.GetPublicKey(0));
                res2 = p->Decrypt(pclient.km.GetPrivateKey(1));
            } else if (ptype == EncryptedPackage) {
                res2 = p->Decrypt(pclient.km.GetPrivateKey(1));
            }
            if (ptype == EncryptedPackage) {
                cout << "(encrypted)";
            } else if (ptype == SignedPackage) {
                cout << "(signed)";
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
    bool lostconn = false;
    while (cin >> Buffer) {
        if (!pclient.sock->Connected()) {
            lostconn = true;
            if (strcmp(Buffer, "exit") == 0) {
                pclient.pm.StopRecieve();
                pclient.sock->Disconnect();
                delete pclient.sock;
                return 0;
            }
            pclient.sock->Connect();
        }
        while (!pclient.sock->Connected()) {
            cout << "Type anything to reconnect or \"exit\" to close client:";
            cin >> Buffer;
            if (strcmp(Buffer, "exit") == 0) {
                pclient.sock->Disconnect();
                delete pclient.sock;
                return 0;
            }
            pclient.sock->Connect();
        }
        if (lostconn) {
            lostconn = false;
            cout << "Connected" << endl;
            cin >> Buffer;
        }
        if (strcmp(Buffer, "exit") == 0) {
            pclient.pm.StopRecieve();
            pclient.sock->Disconnect();
            break;
        }
        p = new Package(0, 0);
        p->Write((byte *)Buffer, PACKDATASIZE);
        p->Encrypt(pclient.km.GetPublicKey(0));
        p->Sign(pclient.km.GetPrivateKey(1));
        p->Send(pclient.sock);
        delete p;
    }
    handle.wait();
    delete pclient.sock;
    return 0;
}

void Recieved(LPVOID lp, LPPackageManager pm) {}

void Disconnected(LPVOID lp, LPSocket sock, int error) {
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
