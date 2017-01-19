#include <cstdio>
#include "PerditClient.h"

using namespace std;

#define PUBUSERKEY "rsauserpub.key"
#define PRIVUSERKEY "rsauserpriv.key"
#define READ(B, BS, BR) (BR = getline(&B, &BS))

enum {
    NONECMD = 0,
    CMDInvalid,
    CMDExit,
    CMDUser,
    CMDUsers,
    CMDMyID,
    CMDHelp,
    CMDUserID
};

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

int ParseCMD(char *Buffer, size_t BufSize) {
    if (Buffer[0] != '\\') {
        return NONECMD;
    }
    Buffer++;
    BufSize--;
    if (cmdeq(Buffer, "exit", BufSize)) {
        return CMDExit;
    } else if (cmdeq(Buffer, "user", BufSize)) {
        return CMDUser;
    } else if (cmdeq(Buffer, "users", BufSize)) {
        return CMDUsers;
    } else if (cmdeq(Buffer, "myid", BufSize)) {
        return CMDMyID;
    } else if (cmdeq(Buffer, "userid", BufSize)) {
        return CMDUserID;
    } else if (cmdeq(Buffer, "help", BufSize)) {
        return CMDHelp;
    } else {
        return CMDInvalid;
    }
}

void printhelp() {
    printf("Type \\help to show these message\n");
    printf("Type \\users to get list of connected users\n");
    printf("Type \\user [user] to switch for him\n");
    printf("Type \\userid [id] to switch for user by id\n");
    printf("Type \\myid to get your ID\n");
    printf("Type \\exit to close messager\n");
}

int main(int argc, char *argv[]) {
    char *Buffer = nullptr;
    size_t BuffSize = 0, bytesred;
    uint64_t UserID = 0;
    char User[MAXNAMELEN] = {'\0'};
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
    if (getline(&Buffer, &BuffSize) == EOF) {
        return 0;
    }
    printf("Connecting...\n");
    PerditClient client(sIP, sPort, PRIVUSERKEY, PUBUSERKEY, Buffer);
    while (!client.Connected()) {
        printf("Type anything to reconnect or \"exit\" to close client:");
        if (getline(&Buffer, &BuffSize) == EOF ||
            ParseCMD(Buffer, BuffSize) == CMDExit) {
            return 0;
        }
        client.Connect();
    }
    printf("Connected\n");
    printhelp();
    bool lostconn = false;
    int cmd;
    while (READ(Buffer, BuffSize, bytesred) != EOF) {
        cmd = ParseCMD(Buffer, BuffSize);
        if (!client.Connected()) {
            lostconn = true;
            if (cmd == CMDExit) {
                return 0;
            }
            client.Connect();
        }
        while (!client.Connected()) {
            printf("Type anything to reconnect or \"\\exit\" to close client:");
            if (READ(Buffer, BuffSize, bytesred) == EOF ||
                ParseCMD(Buffer, BuffSize) == CMDExit) {
                return 0;
            }
            cmd = ParseCMD(Buffer, BuffSize);
            client.Connect();
        }
        if (lostconn) {
            lostconn = false;
            printf("Connected\n");
            continue;
        }
        if (cmd == CMDExit) {
            client.Disconnect();
            break;
        }
        if (!client.Active()) {
            fprintf(stderr, "Waiting for server\n");
            continue;
        }
        if (cmd == CMDUsers) {
            for (auto i : client.GetContactList()) {
                printf("%s (%llu)\n", i->Nickname, i->UserID);
            }
            continue;
        } else if (cmd == CMDUser) {
            UserID = 0;
            if (bytesred > 6) {
                memcpy(User, &Buffer[6],
                       (bytesred - 6 > MAXNAMELEN - 1 ? MAXNAMELEN
                                                      : bytesred - 5));
            }
            continue;
        } else if (cmd == CMDUserID) {
            User[0] = '\0';
            if (bytesred > 8) {
                sscanf(&Buffer[8], "%llu", &UserID);
            }
            continue;
        } else if (cmd == CMDMyID) {
            printf("[%llu]\n", client.ID());
            continue;
        } else if (cmd == CMDHelp) {
            printhelp();
            continue;
        } else if (cmd == CMDInvalid) {
            printf("No such command!\n");
            continue;
        } else if (!User[0] && !UserID) {
            printf("Specify user first!\n");
            continue;
        }
        if (User[0] && client.SendMessage(Buffer, bytesred, User)) {
            printf("No such user!!\n");
        } else if (UserID && client.SendMessage(Buffer, bytesred, UserID)) {
            printf("No such user!!\n");
        }
    }
    return 0;
}
