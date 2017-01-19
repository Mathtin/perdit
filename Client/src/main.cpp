#include <cstdio>
#include "PerditClient.h"

using namespace std;

#define PUBUSERKEY "rsauserpub.txt"
#define PRIVUSERKEY "rsauserpriv.txt"

size_t getline(char **lineptr, size_t *n, char del) {
    char *bufptr = NULL;
    char *p = bufptr;
    size_t size;
    int c;

    if (lineptr == NULL) {
        return -1;
    }
    if (n == NULL) {
        return -1;
    }
    bufptr = *lineptr;
    size = *n;

    c = fgetc(stdin);
    if (c == EOF) {
        return -1;
    }
    if (bufptr == NULL) {
        bufptr = (char *)malloc(128);
        if (bufptr == NULL) {
            return -1;
        }
        size = 128;
    }
    p = bufptr;
    while (c != EOF) {
        if ((p - bufptr) > (size - 1)) {
            size = size + 128;
            bufptr = (char *)realloc(bufptr, size);
            if (bufptr == NULL) {
                return -1;
            }
        }
        if (del == ' ' && isspace(c)) {
            break;
        } else if (c == del) {
            break;
        }
        *p++ = c;
        c = fgetc(stdin);
    }

    *p++ = '\0';
    *lineptr = bufptr;
    *n = size;

    return p - bufptr - 1;
}

int main(int argc, char *argv[]) {
    char *Buffer = nullptr;
    size_t BuffSize = 0;
    char *User = nullptr;
    size_t UserSize = 0;
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
    if (getline(&Buffer, &BuffSize, ' ') == EOF) {
        return 0;
    }
    printf("Connecting...\n");
    PerditClient client(sIP, sPort, PRIVUSERKEY, PUBUSERKEY, Buffer);
    while (!client.Connected()) {
        printf("Type anything to reconnect or \"exit\" to close client:");
        if (getline(&Buffer, &BuffSize, ' ') == EOF ||
            strcmp(Buffer, "exit") == 0) {
            return 0;
        }
        client.Connect();
    }
    printf("Connected\n");
    printf("Type \\users to get list of connected users\n");
    printf("Type \\user [user] to switch for him\n");
    printf("Type \\exit to close messager\n");
    bool lostconn = false;
    while (getline(&Buffer, &BuffSize, ' ') != EOF) {
        if (!client.Connected()) {
            lostconn = true;
            if (strcmp(Buffer, "\\exit") == 0) {
                return 0;
            }
            client.Connect();
        }
        while (!client.Connected()) {
            printf("Type anything to reconnect or \"\\exit\" to close client:");
            if (getline(&Buffer, &BuffSize, ' ') == EOF ||
                strcmp(Buffer, "\\exit") == 0) {
                return 0;
            }
            client.Connect();
        }
        if (lostconn) {
            lostconn = false;
            printf("Connected\n");
            continue;
        }
        if (strcmp(Buffer, "\\exit") == 0) {
            client.Disconnect();
            break;
        }
        if (!client.Active()) {
            fprintf(stderr, "Waiting for server\n");
            continue;
        }
        if (strcmp(Buffer, "\\users") == 0) {
            for (auto i : client.GetContactList()) {
                printf("%s (%llu)\n", i->Nickname, i->UserID);
            }
            continue;
        } else if (strcmp(Buffer, "\\user") == 0) {
            if (getline(&User, &UserSize, ' ') == EOF) {
                return 0;
            }
            continue;
        } else if (!User || !User[0]) {
            printf("Specify user first!\n");
            continue;
        }
        if (client.SendMessage(Buffer, strlen(Buffer), User)) {
            printf("No such user!!\n");
        }
    }
    return 0;
}
