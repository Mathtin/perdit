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
    int num;
    LPPerditUser cl;
    while (cin >> Buffer) {
        if (strcmp(Buffer, "exit") == 0) {
            break;
        }
        num = atoi(Buffer);
        cin >> Buffer;
        if (num == 0) {
            continue;
        }
        cl = NULL;
        for (auto i = serv.Users().begin(); i != serv.Users().end();
             i++, num--) {
            if (num == 1) {
                cl = i->second;
                break;
            }
        }
        if (!cl) {
            continue;
        }
        serv.Send(Buffer, PACKDATASIZE, cl, true);
    }
    serv.Stop();
    return 0;
}
