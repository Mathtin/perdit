#include "RSAKeyManager.h"

RSAKeyManager::RSAKeyManager() {}

RSAKeyManager::~RSAKeyManager() {}

int RSAKeyManager::NewKey() {
    AutoSeededRandomPool rng;
    InvertibleRSAFunction keyPair;
    keyPair.Initialize(rng, RSAKeySizeBits);

    pkey.AssignFrom(keyPair);
    prkey.AssignFrom(keyPair);
    RSA::PrivateKey prkey(keyPair);
    PublicKeyBin.Clear();
    pkey.DEREncode(PublicKeyBin);
    PublicKeyBin.MessageEnd();
    return 0;
}

int RSAKeyManager::Load(const char *pubKeyFile, const char *privKeyFile) {

    // Load public
    if (pubKeyFile) {
        ByteQueue bytes;
        FileSource file(pubKeyFile, true, new Base64Decoder);
        file.TransferTo(bytes);
        bytes.MessageEnd();
        pkey.Load(bytes);
        PublicKeyBin.Clear();
        pkey.DEREncode(PublicKeyBin);
        PublicKeyBin.MessageEnd();
    }
    // Load private
    if (privKeyFile) {
        ByteQueue bytes;
        FileSource file(privKeyFile, true, new Base64Decoder);
        file.TransferTo(bytes);
        bytes.MessageEnd();
        prkey.Load(bytes);
    }

    return 0;
}

int RSAKeyManager::Save(const char *pubKeyFile, const char *privKeyFile) {

    // Save private
    if (privKeyFile) {
        Base64Encoder privkeysink(new FileSink(privKeyFile));
        prkey.DEREncode(privkeysink);
        privkeysink.MessageEnd();
    }
    // Save public
    if (pubKeyFile) {
        Base64Encoder pubkeysink(new FileSink(pubKeyFile));
        pkey.DEREncode(pubkeysink);
        pubkeysink.MessageEnd();
    }
    return 0;
}

RSA::PublicKey &RSAKeyManager::GetPublicKey() {
    return pkey;
}

RSA::PrivateKey &RSAKeyManager::GetPrivateKey() {
    return prkey;
}

const byte *RSAKeyManager::GetPublicKeyBin(size_t &size) {
    return PublicKeyBin.Spy(size);
}
