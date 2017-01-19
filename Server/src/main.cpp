#include <iostream>
#include <cstdio>
#include <cstring>
#include "PerditServer.h"

using namespace std;
// using namespace CryptoPP;

#define PUBSERVKEY "rsaserverpub.txt"
#define PRIVSERVKEY "rsaserverpriv.txt"

int main(int argc, char *argv[]) {
    /*ByteQueue bt;
    RSAKeyManager km;
    km.NewKey();
    auto key = km.GetPrivateKey();
    key.DEREncode(bt);
    size_t size;
    bt.Spy(size);
    cout << bt.MaxRetrievable() << ' ' << size << endl;*/
    cout << " [*] Starting Perdit Server" << endl;
    PerditServer serv("6767", PRIVSERVKEY, PUBSERVKEY);
    cout << " [*] Perdit Server Started" << endl;
    char Buffer[PACKSIZE];
    char Buffer2[MAXNAMELEN];
    LPPerditUser cl;
    while (cin >> Buffer) {
        if (strcmp(Buffer, "exit") == 0) {
            break;
        }
        cin >> Buffer2;
        cl = NULL;
        for (auto i : serv.Users()) {
            if (strncmp(Buffer, i.second->GetNickname(), MAXNAMELEN) == 0) {
                cl = i.second;
                break;
            }
        }
        if (!cl) {
            cout << " [!] No such user: " << Buffer << endl;
            continue;
        }
        serv.SendMessageFor(cl, 0, (byte *)Buffer2, PACKDATASIZE);
    }
    serv.Stop();
    return 0;
}
