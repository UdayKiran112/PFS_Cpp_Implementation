#include"Lib/arch.h"
#include"Lib/core.h"
#include"Lib/randapi.h"
#include"Lib/big_B256_56.h"
#include"Lib/ecp_Ed25519.h"
#include"Lib/ecdh_Ed25519.h"

class Key{
    private:
        int privateKey;
        int publicKey; // will change
    public:
        Key();
        Key(int privateKey);
        int getPrivateKey();
        int getPublicKey();
        void setPrivateKey(int privateKey);
        void setPublicKey(int publicKey);

        void PointGeneration(Ed25519::ECP G);
        int generatePublicKey(octet *secretKey, octet *publicKey, Ed25519::ECP *generatorPoint);
        int generatePrivateKey(csprng *randomNumberGenerator, octet *secretKey);
};