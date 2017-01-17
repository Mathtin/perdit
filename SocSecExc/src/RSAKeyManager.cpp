#include "RSAKeyManager.h"

RSAKeyManager::RSAKeyManager() {}

RSAKeyManager::~RSAKeyManager() {
    for (auto &i : keys) {
        if (i.second.first)
            delete i.second.first;
        if (i.second.second)
            delete i.second.second;
    }
}

int RSAKeyManager::NewKey(uint64_t id) {
    AutoSeededRandomPool rng;
    InvertibleRSAFunction keyPair;
    keyPair.Initialize(rng, RSAKeySizeBits);

    RSA::PublicKey *pubkey = new RSA::PublicKey(keyPair);
    RSA::PrivateKey *privkey = new RSA::PrivateKey(keyPair);

    auto search = keys.find(id);
    if (search == keys.end()) {
        keys[id] = std::make_pair(privkey, pubkey);
    } else {
        if (search->second.first)
            delete search->second.first;
        if (search->second.second)
            delete search->second.second;
        keys[id] = std::make_pair(privkey, pubkey);
    }
    return 0;
}

int RSAKeyManager::Load(const char *pubKeyFile, const char *privKeyFile,
                        uint64_t id) {
    auto search = keys.find(id);
    if (search != keys.end()) {
        if (search->second.first)
            delete search->second.first;
        if (search->second.second)
            delete search->second.second;
    }

    RSA::PublicKey *pubkey = nullptr;
    RSA::PrivateKey *privkey = nullptr;

    // Load public
    if (pubKeyFile) {
        pubkey = new RSA::PublicKey;
        CryptoPP::ByteQueue bytes;
        FileSource file(pubKeyFile, true, new Base64Decoder);
        file.TransferTo(bytes);
        bytes.MessageEnd();
        pubkey->Load(bytes);
    }
    // Load private
    if (privKeyFile) {
        privkey = new RSA::PrivateKey;
        CryptoPP::ByteQueue bytes;
        FileSource file(privKeyFile, true, new Base64Decoder);
        file.TransferTo(bytes);
        bytes.MessageEnd();
        privkey->Load(bytes);
    }

    keys[id] = std::make_pair(privkey, pubkey);

    return 0;
}

int RSAKeyManager::Save(const char *pubKeyFile, const char *privKeyFile,
                        uint64_t id) {
    auto search = keys.find(id);
    if (search == keys.end()) {
        return RSAKEY_SAVE_FAILED;
    }
    auto &keyPair = search->second;
    // Save private
    if (privKeyFile && keyPair.first) {
        Base64Encoder privkeysink(new FileSink(privKeyFile));
        keyPair.first->DEREncode(privkeysink);
        privkeysink.MessageEnd();
    }
    // Save public
    if (pubKeyFile && keyPair.second) {
        Base64Encoder pubkeysink(new FileSink(pubKeyFile));
        keyPair.second->DEREncode(pubkeysink);
        pubkeysink.MessageEnd();
    }
    return 0;
}

int RSAKeyManager::Delete(uint64_t id) {
    auto search = keys.find(id);
    if (search == keys.end()) {
        return RSAKEY_NOT_FOUND;
    }
    keys.erase(search);
    return 0;
}

RSA::PublicKey &RSAKeyManager::GetPublicKey(uint64_t id) {
    return *keys[id].second;
}

RSA::PrivateKey &RSAKeyManager::GetPrivateKey(uint64_t id) {
    return *keys[id].first;
}

std::pair<RSA::PrivateKey *, RSA::PublicKey *> &RSAKeyManager::
    operator[](uint64_t id) {
    return keys[id];
}
