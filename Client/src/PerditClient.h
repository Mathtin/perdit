#ifndef PerditClient_H
#define PerditClient_H

#include <vector>
#include <map>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <Socket.h>
#include <RSAKeyManager.h>
#include <PackageManager.h>

class PerditClient;
typedef PerditClient *LPPerditClient;

enum {
    CTRLHandshake = 1,
    CTRLSeveralPackages,
    CTRLNewMessage,
    CTRLMessageAccepted,
    CTRLContactList,
    CTRLContactListEnd,
    CTRLContactError
};
static const size_t MAXNAMELEN = 32;

struct Contact {
    Contact(char *nick, uint64_t uid) : UserID(uid) {
        memcpy(Nickname, nick, MAXNAMELEN);
    }
    char Nickname[MAXNAMELEN];
    uint64_t UserID;
};

class PerditClient {
  public:
    PerditClient(const char *sIP, const char *sPort, const char *PrivateKeyFile,
                 const char *PublicKeyFile, const char *nick);
    ~PerditClient();
    bool Active();
    bool Connected();
    void Connect();
    void Disconnect();

    uint64_t ID();
    void SetNickname(const char *nick);
    const char *GetNickname();
    const std::vector<Contact *> &GetContactList();

    int SendMessage(const char *msg, size_t size, const char *nick);
    int SendMessage(const char *msg, size_t size, uint64_t uid);

  private:
    RSAKeyManager km;
    PackageManager pm;
    LPConnectingSocket sock;
    uint64_t id;
    RSA::PublicKey ServKey;
    bool HandShaked, startedRecievingContactsList;
    uint64_t PackagesSended;
    char NickName[MAXNAMELEN];
    HANDLE hPackageProcessRoutine;
    std::vector<Contact *> ContactList;
    DWORD WINAPI PackageProcessRoutine();
    void SendHandshake(uint64_t userIDN);
    void AskForContactList();
    const char *NickNameByUID(uint64_t uid);
    uint64_t UIDByNickname(const char *nick);
    void Send(const byte *data, size_t size);
    // Static Members
    static void OnDisconnection(LPVOID lp, LPSocket sock, int error);
};

#endif // !PerditClient_H
