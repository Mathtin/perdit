#include <iostream>
#include <cstring>
#include <future>
#include <Socket.h>
#include <RSAKeyManager.h>
#include <PackageManager.h>

using namespace std;
using namespace CryptoPP;
enum { CTRLHandshake = 1 };

#define PUBUSERKEY "rsauserpub.txt"
#define PRIVUSERKEY "rsauserpriv.txt"

struct PreClient {
    RSAKeyManager km;
    PackageManager pm;
    LPConnectingSocket sock;
    uint64_t id;
    RSA::PublicKey ServKey;
    bool HandShaked;
    uint64_t PackagesSended;
};

typedef PreClient *LPPreClient;

void Recieved(LPVOID lp, LPPackageManager pm);

void Disconnected(LPVOID lp, LPSocket sock, int error);

int main(int argc, char *argv[]) {
    char Buffer[PACKDATASIZE];
    PreClient pclient;
    pclient.HandShaked = false;
    pclient.PackagesSended = 0;
    pclient.km.Load(PUBUSERKEY, PRIVUSERKEY);
    Package *p;
    cout << "Connecting..." << endl;
    const char *sIP;
    if (argc > 1) {
        sIP = argv[1];
    } else {
        sIP = "127.0.0.1";
    }
    pclient.sock = new ConnectingSocket(sIP, "6767");
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
    auto PackageProcessRoutine = [&pclient]() {
        byte Buffer[PACKDATASIZE];
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
                res1 = p->Verify(pclient.ServKey);
                res2 = p->Decrypt(pclient.km.GetPrivateKey());
            } else if (ptype == EncryptedPackage) {
                res2 = p->Decrypt(pclient.km.GetPrivateKey());
            } else if (ptype == OpenPackage) {
                p->Read((byte *)Buffer, PACKDATASIZE);
                if (Buffer[0] == CTRLHandshake) {
                    uint64_t userID = ntohll(*(uint64_t *)(Buffer + 1));
                    pclient.id = userID;
                    ByteQueue bytes;
                    bytes.Put(Buffer + 2 + sizeof(uint64_t),
                              (size_t)Buffer[1 + sizeof(uint64_t)]);
                    bytes.MessageEnd();
                    pclient.ServKey.Load(bytes);
                    pclient.HandShaked = true;
                    printf("Handshake from server\n");
                    Package phand(1, pclient.PackagesSended);
                    uint64_t userIDN = htonll(userID);
                    byte CTRL = CTRLHandshake, bkeysize;
                    size_t keysize;
                    const byte *binkey = pclient.km.GetPublicKeyBin(keysize);
                    bkeysize = keysize;
                    phand.Write(&CTRL, 1);
                    phand.Write((byte *)&userIDN, sizeof(uint64_t));
                    phand.Write(&bkeysize, 1);
                    phand.Write(binkey, keysize);
                    phand.Send(pclient.sock);
                    pclient.PackagesSended++;
                }
                delete p;
                continue;
            } else {
                delete p;
                continue;
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
            p->Read(Buffer, PACKSIZE);
            delete p;
            Buffer[PACKSIZE - 1] = 0;
            cout << '>' << Buffer << '<' << endl;
        }
    };
    auto handle = std::async(std::launch::async, PackageProcessRoutine);
    bool lostconn = false;
    while (cin >> Buffer) {
        if (!pclient.sock->Connected()) {
            pclient.HandShaked = false;
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
            pclient.pm.RecieveFrom(pclient.sock, &Disconnected, &pclient);
            lostconn = false;
            cout << "Connected" << endl;
            cin >> Buffer;
        }
        if (strcmp(Buffer, "exit") == 0) {
            pclient.pm.StopRecieve();
            pclient.sock->Disconnect();
            break;
        }
        if (!pclient.HandShaked) {
            cerr << "Waiting for handshake" << endl;
            continue;
        }
        p = new Package(pclient.id, pclient.PackagesSended);
        p->Write((byte *)Buffer, PACKDATASIZE);
        p->Encrypt(pclient.ServKey);
        p->Sign(pclient.km.GetPrivateKey());
        p->Send(pclient.sock);
        pclient.PackagesSended++;
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
