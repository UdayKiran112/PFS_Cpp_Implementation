#include <bits/stdc++.h>
#include "TA.h"
using namespace std;

static bool signatureKeyGeneration(csprng *RNG, octet *groupPrivateKey, octet *vehiclePublicKey, octet *SignatureKey, octet *A);
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

    // Add (registrationId, vehiclePublicKey) to the map
    auto dict = this->getDictionary();
    dict.push_back(make_pair(*registrationId, *vehiclePublicKey));
    this->setDictionary(dict);

    // Initialize SignatureKey and A
    char sigKeyBuff[2 * EFS_Ed25519 + 1];
    SignatureKey->len = 2 * EFS_Ed25519 + 1;
    SignatureKey->max = sizeof(sigKeyBuff);
    SignatureKey->val = sigKeyBuff;

    // Correct initialization of A
    A->val = new char[2 * EFS_Ed25519 + 1]; // Allocate memory directly to A->val
    A->max = 2 * EFS_Ed25519 + 1;           // Set the maximum length
    A->len = 0;                             // Initialize length to 0, it will be set properly in signatureKeyGeneration

    // Copy data to A
    // No need to copy from aBuff, as A->val is already allocated
    A->len = 65;

    // Do not delete A->val here; manage its lifecycle outside this function

    // Generate signatureKey and A

    // allocate mem to temp
    char tempbuff[EGS_Ed25519];
    octet temp;
    temp.len = EGS_Ed25519;
    temp.max = sizeof(tempbuff);
    temp.val = tempbuff;

    temp = this->groupKey.getPrivateKey();
    if (temp.len == 0)
    {
        cout << "Group private key is not valid." << endl;
        return; // Handle this case as needed
    }

    bool sigGen = signatureKeyGeneration(RNG, &temp, vehiclePublicKey, SignatureKey, A);
    if (!sigGen)
    {
        cout << "Signature generation failed" << endl;
        return;
    }
    else
    {
        cout << "Signature generated successfully" << endl
             << endl;
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
    // TODO: Check if registrationId is valid
    return true;
}

static bool signatureKeyGeneration(csprng *RNG, octet *groupPrivateKey, octet *vehiclePublicKey, octet *SignatureKey, octet *A)
{
    // Generate a random key
    Key randomKey(RNG);

    // Concatenate vehicle public key and random private key
    auto publicKey = randomKey.getPublicKey();
    OCT_copy(A, &publicKey);

    // Debug Print
    cout << "Public Key length: " << publicKey.len << ", max: " << publicKey.max << endl;
    cout << "A length: " << A->len << ", max: " << A->max << endl;

    Ed25519::ECP Apoint;
    Ed25519::ECP_fromOctet(&Apoint, A);

    cout << "A point: ";
    Ed25519::ECP_output(&Apoint);
    cout << endl;

    // Ensure 'result' is properly initialized to handle the concatenation
    int total_len = vehiclePublicKey->len + publicKey.len;
    char res[total_len];
    octet result = {0, static_cast<int>(sizeof(res)), res};

    Message::Concatenate_octet(vehiclePublicKey, &publicKey, &result);

    // Hash the concatenated result into a temporary hash result
    octet hashResult;
    Message::Hash_Function(HASH_TYPE_Ed25519, &result, &hashResult);

    // Multiply the random private key by the hash result
    auto privateKey = randomKey.getPrivateKey();
    char prod[EGS_Ed25519];
    octet product = {0, sizeof(prod), prod};
    Message::multiply_octet(&privateKey, &hashResult, &product);

    // Ensure lengths are valid before adding
    if (groupPrivateKey->len == 0 || product.len == 0 || SignatureKey->len == 0)
    {
        cout << "Error: Invalid lengths - groupPrivateKey length: " << groupPrivateKey->len
             << ", product length: " << product.len << ", SignatureKey length: " << SignatureKey->len << endl;
        return false;
    }

    Message::add_octets(groupPrivateKey, &product, SignatureKey);

    cout << "Signature Key: ";
    OCT_output(SignatureKey);
    cout << endl;

    // Clean up
    delete[] hashResult.val;
    delete[] product.val;
    delete[] publicKey.val;

    return true;
}
