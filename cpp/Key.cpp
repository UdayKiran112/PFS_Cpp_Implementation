#include <bits/stdc++.h>
#include "Key.h"
using namespace std;

Key::Key() {}
Key::Key(csprng *RNG)
{
    if (RNG == nullptr)
    {
        throw invalid_argument("Random Number Generator is null");
    }
    char priv_key[EGS_Ed25519];
    octet priv = {0, sizeof(priv_key), priv_key};
    generatePrivateKey(RNG, &priv);
    this->setPrivateKey(priv);

    char pub_key[2 * EFS_Ed25519 + 1];
    octet pub = {0, sizeof(pub_key), pub_key};
    Ed25519::ECP G;
    PointGeneration(&G);
    generatePublicKey(&priv, &pub, &G);
    this->setPublicKey(pub);
}
octet Key::getPrivateKey()
{
    return privateKey;
}
octet Key::getPublicKey()
{
    char *cpy=new char[2 * EFS_Ed25519 + 1];
    octet copy={0, 2 * EFS_Ed25519 + 1, cpy};
    OCT_copy(&copy, &publicKey);
    return copy;
}
void Key::setPrivateKey(octet privateKey)
{
    this->privateKey = privateKey;
}
void Key::setPublicKey(octet publicKey)
{
    this->publicKey = publicKey;
}

// Process a random BIG r by RFC7748 (for Montgomery & Edwards curves only)
static void RFC7748(B256_56::BIG r)
{
    using namespace B256_56;
    int c, lg = 0;
    BIG t;
    c = Ed25519::CURVE_Cof_I;
    while (c != 1)
    {
        lg++;
        c /= 2;
    }
    int n = 8 * EGS_Ed25519 - lg + 1;
    BIG_mod2m(r, n);
    BIG_zero(t);
    BIG_inc(t, 1);
    BIG_shl(t, n);
    BIG_add(r, r, t);
    c = BIG_lastbits(r, lg);
    BIG_dec(r, c);
    //    printf("lg= %d n=%d\n",lg,n);
}

void Key::PointGeneration(Ed25519::ECP *G)
{
    using namespace Ed25519;

    ECP P;
    bool gen = ECP_generator(&P);

    if (gen == 0)
    {
        throw runtime_error("Point Generation Failed");
    }
    if (ECP_isinf(&P) == 1)
    {
        throw runtime_error("Generated point is at infinity");
    }
    else
    {
        ECP_copy(G, &P);
        cout << "Point generated" << endl;
        ECP_output(G);
    }
}

int Key::generatePrivateKey(csprng *randomNumberGenerator, octet *PrivateKey)
{
    using namespace Ed25519;
    using namespace B256_56;

    BIG secret;

    if (randomNumberGenerator != nullptr)
    {
        BIG_random(secret, randomNumberGenerator);
    }
    else
    {
        BIG_fromBytes(secret, PrivateKey->val);
    }

    RFC7748(secret); // For Montgomery or Edwards, apply RFC7748 transformation

    PrivateKey->len = EGS_Ed25519;
    BIG_toBytes(PrivateKey->val, secret);

    return 0;
}

int Key::generatePublicKey(octet *PrivateKey, octet *publicKey, Ed25519::ECP *generatorPoint)
{
    using namespace Ed25519;
    using namespace B256_56;
    int res = 0;
    BIG secret, curve_order;

    BIG_rcopy(curve_order, CURVE_Order);

    BIG_fromBytes(secret, PrivateKey->val);
    ECP_clmul(generatorPoint, secret, curve_order);
    ECP_toOctet(publicKey, generatorPoint, false);

    // Validating Public Key
    res = Ed25519::ECP_PUBLIC_KEY_VALIDATE(publicKey);
    if (res != 0)
    {
        cout << " ECP Public Key Validation Failed " << endl;
        return -1;
    }
    return res;
}