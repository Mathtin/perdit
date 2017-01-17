#include "RSACrypter.h"

RSACrypter::RSACrypter() : blockSize(0) {}

RSACrypter::RSACrypter(RSA::PrivateKey priv, RSA::PublicKey pub)
    : PrivKey(priv), PubKey(pub) {
    uint32_t PrivSize = PrivKey.MaxImage().ByteCount();
    uint32_t PubSize = PubKey.MaxImage().ByteCount();
    blockSize = (PrivSize >= PubSize ? PubSize : PrivSize);
}

uint32_t RSACrypter::BlockSize() {
    return blockSize;
}
