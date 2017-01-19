#include <cstdio>
#include <cstring>
#include "PerditServer.h"

using namespace std;
// using namespace CryptoPP;

#define PUBSERVKEY "rsaserverpub.key"
#define PRIVSERVKEY "rsaserverpriv.key"
#define READ(B, BS, BR) (BR = getline(&B, &BS))

size_t getline(char **lineptr, size_t *n) {
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
    while (c != EOF && c != '\n') {
        if ((p - bufptr) > (size - 1)) {
            size = size + 128;
            bufptr = (char *)realloc(bufptr, size);
            if (bufptr == NULL) {
                return -1;
            }
        }
        *p++ = c;
        c = fgetc(stdin);
    }

    *p++ = '\0';
    *lineptr = bufptr;
    *n = size;

    return p - bufptr - 1;
}

bool cmdeq(const char *str, const char *cmd, size_t size) {
    while (size--) {
        if (!*cmd && !isalnum(*str)) {
            return true;
        } else if (*cmd != *str) {
            return false;
        }
        cmd++;
        str++;
    }
    return false;
}

void printhelp() {
    printf("Type \\help to show these message\n");
    printf("Type \\users to get list of connected users\n");
    printf("Type \\all [MESSAGE] to send [MESSAGE] for all\n");
    printf("Type \\exit to close messager\n");
    printf("Type [NICKNAME] [MESSAGE] to send [MESSAGE] for [NICKNAME]\n");
}

int main(int argc, char *argv[]) {
    printf(" [*] Starting Perdit Server\n");
    PerditServer serv("6767", PRIVSERVKEY, PUBSERVKEY);
    if (!serv.Active()) {
        system("PAUSE");
        return 1;
    }
    printf(" [*] Perdit Server Started\n");
    printhelp();
    char *Buffer = nullptr;
    size_t BuffSize = 0, bytesred, nicksize;
    LPPerditUser cl;
    while (READ(Buffer, BuffSize, bytesred) != EOF) {
        if (strncmp(Buffer, "", 1) == 0) {
            continue;
        }
        if (cmdeq(Buffer, "\\exit", BuffSize)) {
            break;
        } else if (cmdeq(Buffer, "\\all", BuffSize)) {
            for (auto i : serv.Users()) {
                serv.SendMessageFor(i.second, 0, (byte *)&Buffer[5],
                                    bytesred - 5);
            }
            continue;
        } else if (cmdeq(Buffer, "\\help", BuffSize)) {
            printhelp();
            continue;
        } else if (cmdeq(Buffer, "\\users", BuffSize)) {
            for (auto i : serv.Users()) {
                printf("%s (%llu)\n", i.second->GetNickname(), i.second->ID());
            }
            continue;
        }
        cl = NULL;
        for (auto i : serv.Users()) {
            if (cmdeq(Buffer, i.second->GetNickname(), MAXNAMELEN)) {
                nicksize = strnlen(i.second->GetNickname(), MAXNAMELEN);
                Buffer[nicksize] = '\0';
                cl = i.second;
                break;
            }
        }
        if (!cl) {
            printf(" [!] No such user: %s\n", Buffer);
            continue;
        }
        serv.SendMessageFor(cl, 0, (byte *)&Buffer[nicksize + 1],
                            bytesred - nicksize);
    }
    serv.Stop();
    return 0;
}
