#ifndef PerditServer_H
#define PerditServer_H

#include "Socket.h"
#include <map>
#include <stack>
#include <mutex>
#include <condition_variable>
#include <cstdint>
#include <RSAKeyManager.h>
#include <PackageManager.h>
#include "PerditUser.h"

using namespace CryptoPP;
class PerditServer;
typedef PerditServer *LPPerditServer;

enum {
    CTRLHandshake = 1,
    CTRLSeveralPackages,
    CTRLNewMessage,
    CTRLMessageAccepted,
    CTRLContactList,
    CTRLContactListEnd,
    CTRLContactError
};

struct Task {
    Task(byte t, const byte *data, size_t size, uint64_t idfrom, size_t idfor)
        : type(t), IDFrom(idfrom), IDFor(idfor), BufferSize(size) {
        if (size) {
            Buffer = new byte[size];
        } else {
            Buffer = nullptr;
        }
        memcpy(Buffer, data, size);
    }
    ~Task() {
        if (Buffer) {
            delete Buffer;
        }
    }
    byte type;
    byte *Buffer;
    uint64_t IDFrom, IDFor;
    size_t BufferSize;
};

class PerditServer {
  public:
    PerditServer(const char *sPort, const char *PrivateKeyFile,
                 const char *PublicKeyFile);
    ~PerditServer();

    void Stop();
    std::map<uint64_t, LPPerditUser> &Users();
    bool Active();

    void SendMessageFor(uint64_t uid, uint64_t from, byte *msg, size_t msgsize);
    void SendMessageFor(LPPerditUser user, uint64_t from, byte *msg,
                        size_t msgsize);
    void SendContactList(uint64_t uid);

  private:
    bool bActive;
    uint64_t PackagesSended;
    RSAKeyManager km;
    PackageManager pm;
    LPListeningSocket sock;
    std::map<uint64_t, LPPerditUser> users;
    std::stack<LPPerditUser> oldusers;
    std::stack<Task *> pendingTasks;
    std::mutex mtx;
    std::condition_variable cv;
    HANDLE hPackageProcessRoutine, hTaskProcessRoutine;
    DWORD WINAPI PackageProcessRoutine();
    DWORD WINAPI TaskProcessRoutine();
    int Send(const char *data, size_t size, uint64_t uid, bool encrypt);
    int Send(const char *data, size_t size, LPPerditUser user, bool encrypt);
    // Static Members
    static void OnConnection(LPVOID lp, LPSocket sock, LPSOCKADDR_IN local);
    static void OnDisconnection(LPVOID lp, LPSocket sock, int error);
};

#endif // !PerditServer_H
