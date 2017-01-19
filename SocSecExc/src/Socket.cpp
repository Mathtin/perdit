#include "Socket.h"

#define hCloseSocketEvent Events[0]
#define hAcceptConnectionEvent Events[1]

BOOL Socket::WSAReady = FALSE;
DWORD Socket::dwlOpenedSockets = 0;
WSAData Socket::wsaData;

static uint64_t lrand() {
    return (uint64_t)rand();
}

Socket::Socket() {
    id = lrand() ^ (lrand() << 8) ^ (lrand() << 16) ^ (lrand() << 24) ^
         (lrand() << 32) ^ (lrand() << 40) ^ (lrand() << 48) ^ (lrand() << 56);
    bRecieving = false;
    bOpened = false;
    addr = nullptr;
    SocketAddrInfo = nullptr;
    sock = INVALID_SOCKET;
    RecvFunc = nullptr;
    DiscFunc = nullptr;
    RecvArg = nullptr;
    DiscArg = nullptr;
    BytesSend = 0;
    BytesRecv = 0;
    hRecvThreadHandle = INVALID_HANDLE_VALUE;
    DataBuf.buf = nullptr;
    DataBuf.len = 0;
    Flags = 0;
    ZeroMemory(&Overlapped, sizeof(WSAOVERLAPPED));
    hSocketExit = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hSocketExit == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create event with error: %d",
                WSAGetLastError());
        return;
    }
    int iResult;
    if (!WSAReady) {
        // Initialize Winsock
        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            fprintf(stderr, "WSAStartup failed with error: %d",
                    WSAGetLastError());
            return;
        }
        WSAReady = TRUE;
    }

    // Open Socket
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                     WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Failed to get a socket with error: %d",
                WSAGetLastError());
        return;
    }
    bOpened = true;
    dwlOpenedSockets++;
}

Socket::Socket(SOCKET s) : Socket(s, false, nullptr) {}

Socket::Socket(SOCKET s, bool opened) : Socket(s, opened, nullptr) {}

Socket::Socket(SOCKET s, bool opened, LPSOCKADDR_IN address)
    : sock(s), addr(address), bOpened(opened) {
    id = lrand() ^ (lrand() << 8) ^ (lrand() << 16) ^ (lrand() << 24) ^
         (lrand() << 32) ^ (lrand() << 40) ^ (lrand() << 48) ^ (lrand() << 56);
    bRecieving = false;
    SocketAddrInfo = nullptr;
    RecvFunc = nullptr;
    DiscFunc = nullptr;
    RecvArg = nullptr;
    DiscArg = nullptr;
    BytesSend = 0;
    BytesRecv = 0;
    hRecvThreadHandle = INVALID_HANDLE_VALUE;
    DataBuf.buf = nullptr;
    DataBuf.len = 0;
    Flags = 0;
    ZeroMemory(&Overlapped, sizeof(WSAOVERLAPPED));
    hSocketExit = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hSocketExit == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create event with error: %d",
                WSAGetLastError());
        return;
    }
    if (bOpened) {
        dwlOpenedSockets++;
    }
}

Socket::~Socket() {
    if (bRecieving) {
        SetEvent(hSocketExit);
        WaitForSingleObject(hRecvThreadHandle, INFINITE);
        CloseHandle(hRecvThreadHandle);
    }
    CloseHandle(hSocketExit);
    if (SocketAddrInfo) {
        freeaddrinfo(SocketAddrInfo);
    }
    if (bOpened) {
        closesocket(sock);
        dwlOpenedSockets--;
    }
    if (WSAReady && dwlOpenedSockets == 0) {
        WSACleanup();
        WSAReady = FALSE;
    }
}

struct in_addr Socket::Addr() {
    if (addr) {
        return addr->sin_addr;
    }
    struct in_addr clean;
    ZeroMemory(&clean, sizeof(clean));
    return clean;
}

bool Socket::Opened() {
    return bOpened;
}

bool Socket::Recieving() {
    if (!bOpened) {
        bRecieving = false;
    }
    return bRecieving;
}

uint64_t Socket::SocketID() {
    return id;
}

uint64_t Socket::SetSocketID(uint64_t sid) {
    return id = sid;
}

DWORD Socket::OpenedSockets() {
    return Socket::dwlOpenedSockets;
}

void Socket::Send(char *data, size_t size) {
    send(sock, data, size, 0);
}

int Socket::StartRecieving(RecvSocketFunc f, LPVOID recvarg, DiscSocketFunc df,
                           LPVOID discarg, char *Buffer, size_t BufferSize) {
    RecvFunc = f;
    DiscFunc = df;
    RecvArg = recvarg;
    DiscArg = discarg;
    DataBuf.len = BufferSize;
    DataBuf.buf = Buffer;
    Overlapped.hEvent = WSACreateEvent();
    if (Overlapped.hEvent == WSA_INVALID_EVENT) {
        fprintf(stderr, "WSACreateEvent() failed with error: %d",
                WSAGetLastError());
        return 1;
    }
    Flags = 0;
    bRecieving = WSARecv(sock, &DataBuf, 1, &BytesRecv, &Flags, &Overlapped,
                         NULL) != SOCKET_ERROR ||
                 WSAGetLastError() == ERROR_IO_PENDING;
    if (bRecieving == FALSE) {
        fprintf(stderr, "WSARecv() failed with error: %d", WSAGetLastError());
        return 1;
    }
    hRecvThreadHandle = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)&Socket::RecievingFunc, this, 0, NULL);
    if (hRecvThreadHandle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create RecvThread: %lu\n", GetLastError());
        bRecieving = false;
        return 1;
    }
    return 0;
}

DWORD WINAPI Socket::RecievingFunc() {
    DWORD Index;
    DWORD Flags;
    DWORD BytesTransferred;
    BOOL bRes;
    HANDLE aw[2];
    aw[0] = hSocketExit;
    aw[1] = Overlapped.hEvent;
    while (TRUE) {
        Index = WSAWaitForMultipleEvents(2, aw, FALSE, WSA_INFINITE, FALSE);
        if (Index == WSA_WAIT_FAILED) {
            fprintf(stderr, "WSAWaitForMultipleEvents() failed %d\n",
                    WSAGetLastError());
            return 1;
        }
        if (Index == 0) {
            return 0;
        }
        WSAResetEvent(aw[1]);
        // Check the returns from the overlapped I/O operation on the
        // listening socket
        bRes = WSAGetOverlappedResult(sock, &Overlapped, &BytesTransferred,
                                      FALSE, &Flags);
        if (bRes == FALSE) {
            // Hard disconnect
            bOpened = false;
            bRecieving = false;
            closesocket(sock);
            dwlOpenedSockets--;
            WSACloseEvent(aw[1]);
            if (DiscFunc) {
                DiscFunc(DiscArg, this, WSAGetLastError());
            }
            return 1;
        }
        if (BytesTransferred == 0) {
            // Usual disconnect
            bOpened = false;
            bRecieving = false;
            closesocket(sock);
            dwlOpenedSockets--;
            WSACloseEvent(aw[1]);
            if (DiscFunc) {
                DiscFunc(DiscArg, this, 0);
            }
            return 0;
        }
        if (BytesRecv == 0) {
            BytesRecv = BytesTransferred;
            BytesSend = 0;
        }
        RecvFunc(RecvArg, this, BytesRecv);
        Flags = 0;
        ZeroMemory(&Overlapped, sizeof(WSAOVERLAPPED));
        Overlapped.hEvent = aw[1];
        bRes = WSARecv(sock, &DataBuf, 1, &BytesRecv, &Flags, &Overlapped,
                       NULL) != SOCKET_ERROR ||
               WSAGetLastError() == ERROR_IO_PENDING;
        if (bRes == FALSE) {
            fprintf(stderr, "AcceptEx() failed with error %d\n",
                    WSAGetLastError());
            return 1;
        }
    }
}

DWORD64 ListeningSocket::dwlListeningSockets = 0;

ListeningSocket::ListeningSocket(PCSTR port) {
    int iResult;
    bBinded = false;
    bListening = false;
    bAccepting = false;
    fCallback = nullptr;
    acceptedSocket = INVALID_SOCKET;
    hListeningThread = INVALID_HANDLE_VALUE;
    ListenArg = nullptr;
    Bytes = 0;
    struct addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    // Resolve the server address and port
    iResult = getaddrinfo(NULL, port, &hints, &SocketAddrInfo);
    if (iResult != 0) {
        fprintf(stderr, "getaddrinfo failed with error %d\n",
                WSAGetLastError());
        return;
    }
    addr = (LPSOCKADDR_IN)SocketAddrInfo->ai_addr;
    // Bind Socket
    iResult =
        bind(sock, SocketAddrInfo->ai_addr, (int)SocketAddrInfo->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "bind failed with error %d\n", WSAGetLastError());
        return;
    }
    bBinded = true;
    iResult = listen(sock, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "listen failed %d\n", WSAGetLastError());
        return;
    }
    bListening = true;
    hCloseSocketEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    // Open Accepting Socket
    acceptedSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                               WSA_FLAG_OVERLAPPED);
    if (acceptedSocket == INVALID_SOCKET) {
        fprintf(stderr, "Failed to get accepting socket with error %d\n",
                WSAGetLastError());
        return;
    }
}

ListeningSocket::~ListeningSocket() {
    if (bAccepting) {
        SetEvent(hCloseSocketEvent);
        WaitForSingleObject(hListeningThread, INFINITE);
        CloseHandle(hListeningThread);
    }
    if (bListening) {
        CloseHandle(hCloseSocketEvent);
        CloseHandle(hAcceptConnectionEvent);
    }
}

int ListeningSocket::StartAccepting(AcceptSocketFunc callback, LPVOID arg) {
    fCallback = callback;
    ListenArg = arg;
    hAcceptConnectionEvent = Overlapped.hEvent = WSACreateEvent();
    if (hAcceptConnectionEvent == WSA_INVALID_EVENT) {
        fprintf(stderr, "WSACreateEvent() failed with error %d\n",
                WSAGetLastError());
        return 1;
    }
    bAccepting = AcceptEx(sock, acceptedSocket, (PVOID)acceptBuffer, 0,
                          sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16,
                          &Bytes, &Overlapped) ||
                 WSAGetLastError() == ERROR_IO_PENDING;
    if (bAccepting == FALSE) {
        fprintf(stderr, "AcceptEx() failed with error %d\n", WSAGetLastError());
        return 1;
    }
    hListeningThread = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)&ListeningSocket::ListeningFunc, this,
        0, NULL);
    if (hListeningThread == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create ListeningThread: %lu\n",
                GetLastError());
        bRecieving = false;
        return 1;
    }
    return 0;
}

void ListeningSocket::StopAccepting() {
    if (bAccepting) {
        SetEvent(hCloseSocketEvent);
        WaitForSingleObject(hListeningThread, INFINITE);
        CloseHandle(hListeningThread);
        ResetEvent(hCloseSocketEvent);
        bAccepting = false;
    }
}

bool ListeningSocket::Binded() {
    if (!bOpened) {
        bBinded = false;
    }
    return bBinded;
}

bool ListeningSocket::Listening() {
    if (!Binded()) {
        bListening = false;
    }
    return bListening;
}

bool ListeningSocket::Accepting() {
    if (!Listening()) {
        bAccepting = false;
    }
    return bAccepting;
}

DWORD WINAPI ListeningSocket::ListeningFunc() {
    DWORD Index;
    DWORD Flags = 0;
    DWORD BytesTransferred = 0;
    BOOL bRes;
    while (TRUE) {
        Index = WSAWaitForMultipleEvents(EventsNum, Events, FALSE, WSA_INFINITE,
                                         FALSE);
        if (Index == WSA_WAIT_FAILED) {
            fprintf(stderr, "WSAWaitForMultipleEvents() failed %d\n",
                    WSAGetLastError());
            return 1;
        }
        if (Index == 0) {
            return 0;
        }
        // Check the returns from the overlapped I/O operation on the
        // listening socket
        bRes = WSAGetOverlappedResult(sock, &Overlapped, &BytesTransferred,
                                      FALSE, &Flags);
        if (bRes == FALSE) {
            fprintf(stderr, "WSAGetOverlappedResult() failed with error %d\n",
                    WSAGetLastError());
            return 1;
        }
        // Socket Accepted!
        LPSOCKADDR LocalSockaddr, RemoteSockaddr;
        int LocalSockaddrLength, RemoteSockaddrLength;
        GetAcceptExSockaddrs((PVOID)acceptBuffer, BytesTransferred,
                             sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16,
                             &LocalSockaddr, &LocalSockaddrLength,
                             &RemoteSockaddr, &RemoteSockaddrLength);
        /*struct in_addr addrt = ((LPSOCKADDR_IN)RemoteSockaddr)->sin_addr;
        printf("Connected from: %u.%u.%u.%u\n", (uint)addrt.S_un.S_un_b.s_b1,
               (uint)addrt.S_un.S_un_b.s_b2, (uint)addrt.S_un.S_un_b.s_b3,
               (uint)addrt.S_un.S_un_b.s_b4);*/
        if (fCallback) {
            fCallback(ListenArg, new Socket(acceptedSocket, true,
                                            (LPSOCKADDR_IN)RemoteSockaddr),
                      (LPSOCKADDR_IN)LocalSockaddr);
        } else {
            closesocket(acceptedSocket);
        }

        // New Accepting Socket
        acceptedSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                                   WSA_FLAG_OVERLAPPED);
        if (acceptedSocket == INVALID_SOCKET) {
            fprintf(stderr, "Failed to get accepting socket %d\n",
                    WSAGetLastError());
            return 1;
        }

        WSAResetEvent(hAcceptConnectionEvent);
        ZeroMemory(&Overlapped, sizeof(WSAOVERLAPPED));
        Overlapped.hEvent = hAcceptConnectionEvent;
        bRes = AcceptEx(sock, acceptedSocket, (PVOID)acceptBuffer, 0,
                        sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16,
                        &Bytes, &Overlapped) ||
               WSAGetLastError() == ERROR_IO_PENDING;
        if (bRes == FALSE) {
            fprintf(stderr, "AcceptEx() failed with error %d\n",
                    WSAGetLastError());
            return 1;
        }
    }
}

ConnectingSocket::ConnectingSocket(PCSTR ip, PCSTR port) {
    int iResult;
    struct addrinfo hints;
    bConnected = false;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    iResult = getaddrinfo(ip, port, &hints, &SocketAddrInfo);
    if (iResult != 0) {
        fprintf(stderr, "getaddrinfo failed with error %d\n",
                WSAGetLastError());
        return;
    }
    addr = (LPSOCKADDR_IN)SocketAddrInfo->ai_addr;
    iResult =
        connect(sock, SocketAddrInfo->ai_addr, (int)SocketAddrInfo->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "Connection failed with error %d\n", WSAGetLastError());
        return;
    }
    bConnected = true;
}

ConnectingSocket::~ConnectingSocket() {}

bool ConnectingSocket::Connected() {
    if (!bOpened) {
        bConnected = false;
    }
    return bConnected;
}

int ConnectingSocket::Disconnect() {
    if (bRecieving) {
        SetEvent(hSocketExit);
        WaitForSingleObject(hRecvThreadHandle, INFINITE);
        CloseHandle(hRecvThreadHandle);
    }
    if (bOpened) {
        closesocket(sock);
        dwlOpenedSockets--;
    }
    bRecieving = bOpened = bConnected = false;
    return 0;
}

int ConnectingSocket::Connect() {
    if (bConnected) {
        return 0;
    } else if (!bOpened) {
        // Open Socket
        sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                         WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET) {
            fprintf(stderr, "Failed to get a socket with error: %d",
                    WSAGetLastError());
            return 1;
        }
        bOpened = true;
    }
    int iResult;
    iResult =
        connect(sock, SocketAddrInfo->ai_addr, (int)SocketAddrInfo->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "Connection failed with error %d\n", WSAGetLastError());
        return 1;
    }
    bConnected = true;
    return 0;
}

#undef hCloseSocketEvent
#undef hAcceptConnectionEvent

bool FileExist(const char *name) {
    WIN32_FIND_DATA fdata;
    HANDLE search = FindFirstFile(name, &fdata);
    bool found = search != INVALID_HANDLE_VALUE;
    FindClose(search);
    return found;
}
