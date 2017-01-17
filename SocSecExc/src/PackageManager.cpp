#include "PackageManager.h"

const size_t PackageManager::BufferSize = PACKSIZE << 4;

PackageManager::PackageManager() : bStoppedRecv(false) {}

PackageManager::~PackageManager() {
    LPPackage p;
    while (q.size()) {
        p = Pop();
        delete p;
    }
}

void PackageManager::Push(LPPackage p) {
    std::lock_guard<std::mutex> lock(mtx);
    q.push(p);
}

LPPackage PackageManager::Pop(void) {
    std::lock_guard<std::mutex> lock(mtx);
    if (!q.size()) {
        return nullptr;
    }
    LPPackage p = q.front();
    q.pop();
    return p;
}

void PackageManager::WaitForPackages() {
    std::unique_lock<std::mutex> lck(mtx);
    if (bStoppedRecv) {
        return;
    }
    cv.wait(lck);
}

bool PackageManager::PackagesAvailable() {
    std::lock_guard<std::mutex> lock(mtx);
    return q.size() != 0;
}

size_t PackageManager::NumPackagesAvailable() {
    std::lock_guard<std::mutex> lock(mtx);
    return q.size();
}

bool PackageManager::Recieving() {
    std::lock_guard<std::mutex> lock(mtx);
    return !bStoppedRecv;
}

void PackageManager::StopRecieve() {
    std::unique_lock<std::mutex> lock(mtx);
    bStoppedRecv = true;
    cv.notify_all();
}

void PackageManager::ContinueRecieve() {
    std::lock_guard<std::mutex> lock(mtx);
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
        p = new Package(0, 0);
        p->RawRewrite(pm->Buffer + Offset, toWrite, CTRL & PACKSIGNED,
                      CTRL & PACKENCRYPTED);
        std::unique_lock<std::mutex> lock(pm->mtx);
        pm->q.push(p);
        Recieved -= toWrite;
        Offset += toWrite;
    }
    if (pm->q.size()) {
        pm->cv.notify_all();
    }
}

int PackageManager::RecieveFrom(LPSocket sock, DiscSocketFunc df, LPVOID arg) {
    return sock->StartRecieving(&PackageManager::SocketReciever, this, df, arg,
                                (char *)Buffer, BufferSize);
}

byte *PackageManager::GetBuffer() {
    std::lock_guard<std::mutex> lock(mtx);
    return Buffer;
}

Package::Package(uint64_t uid, uint64_t paid) {
    available = PACKDATASIZE;
    type = OpenPackage;
    *((uint64_t *)(UData + 1)) = htonll(uid);
    *((uint64_t *)(UData + 9)) = htonll(paid);
}

uint32_t Package::Write(const byte *data, uint32_t size) {
    uint32_t used = PACKDATASIZE - available;
    if (!available || type == InvalidPackage || type == EncryptedPackage) {
        return 0;
    }
    uint32_t toWrite = (available > size ? size : available), toWriteBlock,
             blockOffset = PACKFIRSTBLOCKSIZE, written = 0;
    if (toWrite == 0) {
        return written;
    }
    // First block
    byte *Block = UData + 17;
    if (used < blockOffset) {
        toWriteBlock = blockOffset - used;
        if (toWriteBlock > toWrite) {
            toWriteBlock = toWrite;
        }
        memcpy(Block, data + written, toWriteBlock);
        used += toWriteBlock;
        written += toWriteBlock;
        available -= toWriteBlock;
        toWrite -= toWriteBlock;
        blockOffset += PACKBLOCKSIZE;
        Block += PACKFIRSTBLOCKSIZE + PACKSALTSIZE;
    }
    if (toWrite == 0) {
        return written;
        // Second block
    } else if (used < blockOffset) {
        toWriteBlock = blockOffset - used;
        if (toWriteBlock > toWrite) {
            toWriteBlock = toWrite;
        }
        memcpy(Block, data + written, toWriteBlock);
        used += toWriteBlock;
        written += toWriteBlock;
        available -= toWriteBlock;
        toWrite -= toWriteBlock;
        blockOffset += PACKBLOCKSIZE;
        Block += RSAKeySizeBytes;
    }
    if (toWrite == 0) {
        return written;
        // Third block
    } else if (used < blockOffset) {
        toWriteBlock = blockOffset - used;
        if (toWriteBlock > toWrite) {
            toWriteBlock = toWrite;
        }
        memcpy(Block, data + written, toWriteBlock);
        used += toWriteBlock;
        written += toWriteBlock;
        available -= toWriteBlock;
        toWrite -= toWriteBlock;
    }
    return written;
}

uint32_t Package::Read(byte *data, uint32_t size) {
    uint32_t used = PACKDATASIZE - available;
    if (!used || type == InvalidPackage || type == EncryptedPackage) {
        return 0;
    }
    uint32_t toWrite = (used > size ? size : used), toWriteBlock,
             blockOffset = PACKFIRSTBLOCKSIZE, written = 0,
             Offset = used - toWrite;
    if (toWrite == 0) {
        return written;
    }
    // First block
    byte *Block = UData + 17;
    if (Offset < blockOffset) {
        toWriteBlock = blockOffset - Offset;
        if (toWriteBlock > toWrite) {
            toWriteBlock = toWrite;
        }
        memcpy(data + written, Block, toWriteBlock);
        used -= toWriteBlock;
        written += toWriteBlock;
        available += toWriteBlock;
        toWrite -= toWriteBlock;
        Offset = blockOffset;
        blockOffset += PACKBLOCKSIZE;
        Block += PACKFIRSTBLOCKSIZE + PACKSALTSIZE;
    }
    if (toWrite == 0) {
        return written;
        // Second block
    } else if (Offset < blockOffset) {
        toWriteBlock = blockOffset - Offset;
        if (toWriteBlock > toWrite) {
            toWriteBlock = toWrite;
        }
        memcpy(data + written, Block, toWriteBlock);
        used -= toWriteBlock;
        written += toWriteBlock;
        available += toWriteBlock;
        toWrite -= toWriteBlock;
        Offset = blockOffset;
        blockOffset += PACKBLOCKSIZE;
        Block += RSAKeySizeBytes;
    }
    if (toWrite == 0) {
        return written;
        // Third block
    } else if (Offset < blockOffset) {
        toWriteBlock = blockOffset - Offset;
        if (toWriteBlock > toWrite) {
            toWriteBlock = toWrite;
        }
        memcpy(data + written, Block, toWriteBlock);
        used -= toWriteBlock;
        written += toWriteBlock;
        available += toWriteBlock;
        toWrite -= toWriteBlock;
    }
    return written;
}

void Package::ClearData() {
    available = PACKDATASIZE;
}

void Package::Send(Socket *sock) {
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
    } else if (Encrypted) {
        type = EncryptedPackage;
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
    return ntohll(*(uint64_t *)(UData + 1));
}

uint64_t Package::PackageID() {
    return ntohll(*(uint64_t *)(UData + 9));
}

uint32_t Package::Size() {
    return PACKDATASIZE - available;
}

PackageType Package::Type() {
    return type;
}
