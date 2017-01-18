#include <cstdio>
#include "PerditClient.h"

using namespace std;

#define PUBUSERKEY "rsauserpub.txt"
#define PRIVUSERKEY "rsauserpriv.txt"

int main(int argc, char *argv[]) {
    char Buffer[PACKDATASIZE];
    const char *sIP, *sPort;
    if (argc > 1) {
        sIP = argv[1];
    } else {
        sIP = "127.0.0.1";
    }
    if (argc > 2) {
        sPort = argv[2];
    } else {
        sPort = "6767";
    }
    printf("Type your nickname (MAX 31 CHARACTER):");
    if (scanf("%31s", Buffer) == EOF) {
        return 0;
    }
    printf("Connecting...\n");
    PerditClient client(sIP, sPort, PRIVUSERKEY, PUBUSERKEY, Buffer);
    while (!client.Connected()) {
        printf("Type anything to reconnect or \"exit\" to close client:");
        if (scanf("%256s", Buffer) == EOF || strcmp(Buffer, "exit") == 0) {
            return 0;
        }
        client.Connect();
    }
    printf("Connected\n");
    bool lostconn = false;
    while (scanf("%256s", Buffer) != EOF) {
        if (!client.Connected()) {
            lostconn = true;
            if (strcmp(Buffer, "exit") == 0) {
                return 0;
            }
            client.Connect();
        }
        while (!client.Connected()) {
            printf("Type anything to reconnect or \"exit\" to close client:");
            if (scanf("%256s", Buffer) == EOF || strcmp(Buffer, "exit") == 0) {
                return 0;
            }
            client.Connect();
        }
        if (lostconn) {
            lostconn = false;
            printf("Connected\n");
            if (scanf("%256s", Buffer) == EOF) {
                return 0;
            }
        }
        if (strcmp(Buffer, "exit") == 0) {
            client.Disconnect();
            break;
        }
        if (!client.Active()) {
            fprintf(stderr, "Waiting for server\n");
            continue;
        }
        client.Send((byte *)Buffer, PACKDATASIZE);
    }
    return 0;
}
