#include <bits/stdc++.h>
#include "TA.h"
using namespace std;

static bool signatureGeneration(csprng *RNG, octet *groupPrivateKey, octet *vehiclePublicKey, octet *SignatureKey, octet *A);
bool checkRegValid(octet *registrationId);

TA::TA() {}

TA::TA(csprng *RNG)
{
    // only groupKey should be initialized with Key constructor
    this->groupKey = Key(RNG);
}

void TA::validateRequest(csprng *RNG, octet *registrationId, octet *vehiclePublicKey, octet *SignatureKey, octet *A)
{
    auto regValid = checkRegValid(registrationId);
    if (!regValid)
    {
        cout << "Registration ID is not valid" << endl;
        return;
    }
    // add (registrationId, vehiclePublicKey) to the map
    auto dict = this->getDictionary();
    dict.push_back(make_pair(*registrationId, *vehiclePublicKey));
    this->setDictionary(dict);
    // generate signatureKey and A
    auto temp = this->getGroupKey().getPrivateKey();
    bool sigGen = signatureGeneration(RNG, &temp, vehiclePublicKey, SignatureKey, A);
    if (!sigGen)
    {
        cout << "Signature generation failed" << endl;
        return;
    }
}

void TA::setGroupKey(Key groupKey)
{
    this->groupKey = groupKey;
}

Key TA::getGroupKey()
{
    return groupKey;
}

vector<pair<octet, octet>> TA::getDictionary()
{
    return dictionary;
}

void TA::setDictionary(vector<pair<octet, octet>> dictionary)
{
    this->dictionary = dictionary;
}

bool checkRegValid(octet *registrationId)
{
    // TODO
    //  Check if registrationId is valid
    return true;
}

static bool signatureGeneration(csprng *RNG, octet *groupPrivateKey, octet *vehiclePublicKey, octet *SignatureKey, octet *A)
{
    // Generate a random key
    Key randomKey(RNG);

    // Ensure 'result' is properly initialized to handle the concatenation
    char res[2*(2 * EFS_Ed25519 + 1)];
    octet result={0,sizeof(res),res};

    // Concatenate vehicle public key and random private key
    auto publicKey = randomKey.getPublicKey();
    OCT_copy(A, &publicKey);
    Message::Concatenate_octet(vehiclePublicKey, &publicKey, &result);

    // Hash the concatenated result into a temporary hash result
    char hres[HASH_TYPE_Ed25519];
    octet hashResult={0,sizeof(hres),hres};
    Message::Hash_Function(HASH_TYPE_Ed25519,&result, &hashResult);

    // Multiply the random private key by the hash result
    auto privateKey = randomKey.getPrivateKey();
    char prod[EGS_Ed25519];
    octet product={0,sizeof(prod),prod};
    Message::multiply_octet(&privateKey, &hashResult, &product);

    // Add the group private key to the multiplication result
    Message::add_octets(groupPrivateKey, &product, SignatureKey);

    // Clean up
    delete[] result.val;
    delete[] hashResult.val;
    delete[] product.val;
    delete[] publicKey.val;

    return true;
}
