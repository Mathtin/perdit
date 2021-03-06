#include "PackageManager.h"

const size_t PackageManager::BufferSize = PACKSIZE << 4;

PackageManager::PackageManager() : bStoppedRecv(false), PackagesRecieved(0) {
    hNewPackage = CreateEvent(NULL, TRUE, FALSE, NULL);
}

PackageManager::~PackageManager() {
    LPPackage p;
    SetEvent(hNewPackage);
    while (q.size()) {
        p = Pop();
        delete p;
    }
    CloseHandle(hNewPackage);
}

void PackageManager::Push(LPPackage p) {
    std::unique_lock<std::mutex> lck(mtx);
    q.push(p);
}

LPPackage PackageManager::Pop(void) {
    std::unique_lock<std::mutex> lck(mtx);
    if (!q.size()) {
        return nullptr;
    }
    LPPackage p = q.front();
    q.pop();
    return p;
}

void PackageManager::WaitForPackages() {
    if (bStoppedRecv || q.size() != 0) {
        return;
    }
    WaitForSingleObject(hNewPackage, INFINITE);
    ResetEvent(hNewPackage);
}

bool PackageManager::PackagesAvailable() {
    std::unique_lock<std::mutex> lck(mtx);
    return q.size() != 0;
}

size_t PackageManager::NumPackagesAvailable() {
    std::unique_lock<std::mutex> lck(mtx);
    return q.size();
}

bool PackageManager::Recieving() {
    std::unique_lock<std::mutex> lck(mtx);
    return !bStoppedRecv;
}

void PackageManager::StopRecieve() {
    std::unique_lock<std::mutex> lck(mtx);
    bStoppedRecv = true;
    SetEvent(hNewPackage);
}

void PackageManager::ContinueRecieve() {
    std::unique_lock<std::mutex> lck(mtx);
    bStoppedRecv = false;
}

void PackageManager::SocketReciever(LPVOID lp, Socket *s, size_t Recieved) {
    LPPackageManager pm = (LPPackageManager)lp;
    if (pm->bStoppedRecv) {
        return;
    }
    size_t Offset = 0, toWrite = 0;
    byte CTRL;
    LPPackage p;
    while (Recieved) {
        toWrite = (Recieved > PACKSIZE ? PACKSIZE : Recieved);
        CTRL = pm->Buffer[Offset];
        p = new Package(s->SocketID(), pm->PackagesRecieved);
        pm->PackagesRecieved++;
        p->RawRewrite(pm->Buffer + Offset, toWrite, CTRL & PACKSIGNED,
                      CTRL & PACKENCRYPTED);
        std::unique_lock<std::mutex> lock(pm->mtx);
        pm->q.push(p);
        Recieved -= toWrite;
        Offset += toWrite;
    }
    if (pm->q.size()) {
        SetEvent(pm->hNewPackage);
    }
}

int PackageManager::RecieveFrom(LPSocket sock, DiscSocketFunc df, LPVOID arg) {
    std::unique_lock<std::mutex> lck(mtx);
    bStoppedRecv = false;
    return sock->StartRecieving(&PackageManager::SocketReciever, this, df, arg,
                                (char *)Buffer, BufferSize);
}

byte *PackageManager::GetBuffer() {
    std::unique_lock<std::mutex> lck(mtx);
    return Buffer;
}

Package::Package(uint64_t uid, uint64_t paid) : userid(uid), pacid(paid) {
    dbegin = 0;
    dend = 0;
    placed = false;
    available = PACKDATASIZE;
    type = OpenPackage;
    *((uint64_t *)(UData + 1)) = htonll(uid);
    *((uint64_t *)(UData + 9)) = htonll(paid);
}

uint32_t Package::Write(const byte *data, uint32_t size) {
    if (!available || type == InvalidPackage || type == EncryptedPackage ||
        type == SignedPackage) {
        return 0;
    }
    placed = false;
    size_t i;
    for (i = 0; size && available; i++, size--, available--) {
        Data[dend] = data[i];
        dend = (dend + 1) % PACKDATASIZE;
    }
    return i;
}

uint32_t Package::Read(byte *data, uint32_t size) {
    if (available == PACKDATASIZE || type == InvalidPackage ||
        type == EncryptedPackage || type == SignedPackage) {
        return 0;
    }
    size_t i;
    for (i = 0; size && available != PACKDATASIZE; i++, size--, available++) {
        data[i] = Data[dbegin];
        dbegin = (dbegin + 1) % PACKDATASIZE;
    }
    return i;
}

static void PlaceData(byte *Data, byte *UData, size_t dbegin) {
    byte *UBlock = UData + 17;
    // First block
    for (size_t i = 0; i < PACKFIRSTBLOCKSIZE; i++) {
        UBlock[i] = Data[dbegin];
        dbegin = (dbegin + 1) % PACKDATASIZE;
    }
    UBlock += PACKFIRSTBLOCKSIZE + PACKSALTSIZE;
    // Second block
    for (size_t i = 0; i < PACKBLOCKSIZE; i++) {
        UBlock[i] = Data[dbegin];
        dbegin = (dbegin + 1) % PACKDATASIZE;
    }
    UBlock += RSAKeySizeBytes;
    // Third block
    for (size_t i = 0; i < PACKBLOCKSIZE; i++) {
        UBlock[i] = Data[dbegin];
        dbegin = (dbegin + 1) % PACKDATASIZE;
    }
}

static void BackPlaceData(byte *Data, byte *UData) {
    byte *UBlock = UData + 17;
    size_t dbegin = 0;
    // First block
    for (size_t i = 0; i < PACKFIRSTBLOCKSIZE; i++) {
        Data[dbegin] = UBlock[i];
        dbegin = (dbegin + 1) % PACKDATASIZE;
    }
    UBlock += PACKFIRSTBLOCKSIZE + PACKSALTSIZE;
    // Second block
    for (size_t i = 0; i < PACKBLOCKSIZE; i++) {
        Data[dbegin] = UBlock[i];
        dbegin = (dbegin + 1) % PACKDATASIZE;
    }
    UBlock += RSAKeySizeBytes;
    // Third block
    for (size_t i = 0; i < PACKBLOCKSIZE; i++) {
        Data[dbegin] = UBlock[i];
        dbegin = (dbegin + 1) % PACKDATASIZE;
    }
}

void Package::ClearData() {
    available = PACKDATASIZE;
    dbegin = dend = 0;
    placed = false;
    type = OpenPackage;
}

void Package::Send(Socket *sock) {
    if (type == OpenPackage && !placed) {
        PlaceData(Data, UData, dbegin);
        placed = true;
    }
    UData[0] = 0;
    if (type == SignedPackage) {
        UData[0] |= PACKSIGNED | PACKENCRYPTED;
    } else if (type == EncryptedPackage) {
        UData[0] |= PACKENCRYPTED;
    }
    sock->Send((char *)UData, PACKSIZE);
}

uint32_t Package::RawRewrite(const byte *data, uint32_t size, bool Signed,
                             bool Encrypted) {
    uint32_t toWrite = (PACKSIZE > size ? size : PACKSIZE);
    memcpy(UData, data, toWrite);
    available = 0;
    if (Signed) {
        type = SignedPackage;
        placed = false;
    } else if (Encrypted) {
        type = EncryptedPackage;
        placed = false;
    } else {
        type = OpenPackage;
        BackPlaceData(Data, UData);
        dend = 0;
        dbegin = 0;
        placed = true;
    }
    return toWrite;
}

uint32_t Package::WriteSign(const byte *sign) {
    type = SignedPackage;
    memcpy(UData + PACKSIZE - RSAKeySizeBytes, sign, RSAKeySizeBytes);
    return RSAKeySizeBytes;
}

int Package::Sign(RSA::PrivateKey key) {
    if (type == OpenPackage) {
        return ErrorPackageOpened;
    } else if (type == InvalidPackage) {
        return ErrorPackageInvalid;
    }
    AutoSeededRandomPool rng;
    RSASSA_PKCS1v15_SHA_Signer signer(key);
    signer.SignMessage(rng, UData + 1, PACKBLOCKSIZE,
                       UData + PACKSIZE - RSAKeySizeBytes);
    type = SignedPackage;
    return PackageSigned;
}

int Package::Encrypt(RSA::PublicKey key) {
    if (type == SignedPackage) {
        return ErrorPackageSigned;
    } else if (type == InvalidPackage) {
        return ErrorPackageInvalid;
    } else if (type == EncryptedPackage) {
        return ErrorPackageEncrypted;
    }
    if (!placed) {
        PlaceData(Data, UData, dbegin);
        placed = true;
    }
    AutoSeededRandomPool rng;
    RSAES_PKCS1v15_Encryptor encryptor(key);
    byte tmp[PACKBLOCKSIZE];
    // First block
    byte *Block = UData + 1;
    memcpy(tmp, Block, PACKBLOCKSIZE);
    encryptor.Encrypt(rng, tmp, PACKBLOCKSIZE, Block);
    // Second block
    Block += RSAKeySizeBytes;
    memcpy(tmp, Block, PACKBLOCKSIZE);
    encryptor.Encrypt(rng, tmp, PACKBLOCKSIZE, Block);
    // Third block
    Block += RSAKeySizeBytes;
    memcpy(tmp, Block, PACKBLOCKSIZE);
    encryptor.Encrypt(rng, tmp, PACKBLOCKSIZE, Block);
    type = EncryptedPackage;
    return PackageEncrypted;
}

int Package::Decrypt(RSA::PrivateKey key) {
    if (type == OpenPackage) {
        return ErrorPackageOpened;
    } else if (type == InvalidPackage) {
        return ErrorPackageInvalid;
    }
    AutoSeededRandomPool rng;
    RSAES_PKCS1v15_Decryptor decryptor(key);
    byte tmp[RSAKeySizeBytes];
    // First Block
    byte *Block = UData + 1;
    memcpy(tmp, Block, RSAKeySizeBytes);
    decryptor.Decrypt(rng, tmp, RSAKeySizeBytes, Block);
    // Second block
    Block += RSAKeySizeBytes;
    memcpy(tmp, Block, RSAKeySizeBytes);
    decryptor.Decrypt(rng, tmp, RSAKeySizeBytes, Block);
    // Third block
    Block += RSAKeySizeBytes;
    memcpy(tmp, Block, RSAKeySizeBytes);
    decryptor.Decrypt(rng, tmp, RSAKeySizeBytes, Block);
    type = OpenPackage;
    BackPlaceData(Data, UData);
    dend = 0;
    dbegin = 0;
    placed = true;
    return PackageDecrypted;
}

int Package::Verify(RSA::PublicKey key) {
    if (type == EncryptedPackage) {
        return ErrorPackageEncrypted;
    } else if (type == InvalidPackage) {
        return ErrorPackageInvalid;
    } else if (type == OpenPackage) {
        return ErrorPackageOpened;
    }
    RSASSA_PKCS1v15_SHA_Verifier verifier(key);
    bool Signed = verifier.VerifyMessage(UData + 1, PACKBLOCKSIZE,
                                         UData + PACKSIZE - RSAKeySizeBytes,
                                         RSAKeySizeBytes);
    if (Signed) {
        type = SignedPackage;
        return PackageSigned;
    }
    type = InvalidPackage;
    return ErrorPackageInvalid;
}

uint64_t Package::UserID() {
    return userid;
}

uint64_t Package::PackageID() {
    return pacid;
}

uint32_t Package::Size() {
    return PACKDATASIZE - available;
}

PackageType Package::Type() {
    return type;
}
