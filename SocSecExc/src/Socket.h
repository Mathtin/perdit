#ifndef SocketManager_H
#define SocketManager_H

#undef UNICODE
#if defined(_WIN32) || defined(__CYGWIN__)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>
#include <ws2tcpip.h>
#else
#endif
#include "byteconvert.h"

#include <cstdio>
#include <cstdlib>
#include <cstdint>

static const DWORD EventsNum = 2;

class Socket;
class ListeningSocket;
class ConnectingSocket;

typedef Socket *LPSocket;
typedef ListeningSocket *LPListeningSocket;
typedef ConnectingSocket *LPConnectingSocket;

typedef void (*AcceptSocketFunc)(LPVOID, LPSocket, LPSOCKADDR_IN);
typedef void (*RecvSocketFunc)(LPVOID, LPSocket, size_t);
typedef void (*DiscSocketFunc)(LPVOID, LPSocket, int);
typedef unsigned int uint;

class Socket {
  public:
    Socket();
    Socket(SOCKET s);
    Socket(SOCKET s, bool opened);
    Socket(SOCKET s, bool opened, LPSOCKADDR_IN address);
    ~Socket();

    bool Opened();
    uint64_t SocketID();
    uint64_t SetSocketID(uint64_t sid);
    int StartRecieving(RecvSocketFunc f, LPVOID recvarg, DiscSocketFunc df,
                       LPVOID discarg, char *Buffer, size_t BufferSize);
    void Send(char *data, size_t size);

    in_addr Addr();

    static DWORD OpenedSockets();

  protected:
    Socket(const Socket &);
    Socket &operator=(const Socket &);
    uint64_t id;
    SOCKET sock;
    LPSOCKADDR_IN addr;
    struct addrinfo *SocketAddrInfo;
    RecvSocketFunc RecvFunc;
    DiscSocketFunc DiscFunc;
    LPVOID RecvArg, DiscArg;
    HANDLE hRecvThreadHandle, hSocketExit;
    bool bOpened, bRecieving;
    DWORD BytesSend, BytesRecv;
    WSAOVERLAPPED Overlapped;
    WSABUF DataBuf;
    DWORD Flags;
    DWORD WINAPI RecievingFunc();
    // WSA Subsystem
    static BOOL WSAReady;
    static DWORD dwlOpenedSockets;
    static WSAData wsaData;
};

class ListeningSocket : public Socket {
  public:
    ListeningSocket(PCSTR port);
    ~ListeningSocket();

    bool Binded();
    bool Listening();

    int StartAccepting(AcceptSocketFunc callback, LPVOID arg);
    void StopAccepting();

    bool Accepting();

  protected:
    AcceptSocketFunc fCallback;
    bool bBinded, bListening, bAccepting;
    SOCKET acceptedSocket;
    CHAR acceptBuffer[2 * (sizeof(SOCKADDR_IN) + 16)];
    HANDLE hListeningThread;
    HANDLE Events[EventsNum];
    LPVOID ListenArg;

    DWORD WINAPI ListeningFunc();
    // Static members
    static DWORD64 dwlListeningSockets;
};

class ConnectingSocket : public Socket {
  public:
    ConnectingSocket(PCSTR ip, PCSTR port);
    ~ConnectingSocket();

    bool Connected();
    int Disconnect();
    int Connect();

  private:
    bool bConnected;
};

#endif // !SocketManager_H
