#include <bits/stdc++.h>
#include <chrono>
#include "Vehicle.h"
using namespace std;

Vehicle::Vehicle(octet registrationId, Key vehicleKey, octet signatureKey, octet A, TA ta)
{
    this->registrationId = registrationId;
    this->vehicleKey = vehicleKey;
    this->signatureKey = signatureKey;
    this->A = A;
    this->ta = ta;
}

Vehicle::Vehicle() {}

Vehicle::Vehicle(csprng *RNG, TA ta)
{
    this->ta = ta;
    this->vehicleKey = Key(RNG);
}
octet Vehicle::getRegistrationId()
{
    return registrationId;
}

Key Vehicle::getVehicleKey()
{
    return vehicleKey;
}

octet Vehicle::getSignatureKey()
{
    return signatureKey;
}

octet Vehicle::getA()
{
    return A;
}

TA Vehicle::getTA()
{
    return ta;
}

void Vehicle::setRegistrationId(octet registrationId)
{
    this->registrationId = registrationId;
}

void Vehicle::setVehicleKey(Key vehicleKey)
{
    this->vehicleKey = vehicleKey;
}

void Vehicle::setSignatureKey(octet signatureKey)
{
    this->signatureKey = signatureKey;
}

void Vehicle::setA(octet A)
{
    this->A = A;
}

void Vehicle::setTA(TA ta)
{
    this->ta = ta;
}

using namespace core;
using namespace Ed25519;
void Vehicle::requestVerification(csprng *RNG)
{
    octet signkey;
    char pub[2 * EFS_Ed25519 + 1];
    octet virpubkey = {0, sizeof(pub), pub};
    octet publicKey = this->getVehicleKey().getPublicKey();
    auto temp = this->registrationId;
    this->ta.validateRequest(RNG, &temp, &publicKey, &signkey, &virpubkey);
    this->setSignatureKey(signkey);
    this->setA(virpubkey);

    // clean up
    delete[] publicKey.val;
}

// static char *StrtoCharstar(string s)
// {
//     char *c = new char[s.length() + 1];
//     strcpy(c, s.c_str());
//     return c;
// }

// void sendingMessage(csprng *RNG, core::octet vehiclePrivateKey, core::octet signatureKey, string message, octet *B, Message msg, octet *SIG)
// {
//     //
//     bool x = signMessage(RNG, &vehiclePrivateKey, &signatureKey, message, SIG, B, msg);
//     if (!x)
//     {
//         cout << "No Signature Generated";
//         return;
//     }

//     cout << "Signature= 0x";
//     OCT_output(&SIG);
// }

bool Vehicle::signMessage(csprng *RNG, string message, octet *B, Message *msg)
{
    using namespace Ed25519;
    Key randKey(RNG);
    octet signedMessage;
    octet privateKey = this->vehicleKey.getPrivateKey();
    octet signatureKey = this->signatureKey;

    // Generate B
    octet randKeyPublicKey = randKey.getPublicKey();
    OCT_copy(B, &randKeyPublicKey);

    *msg = Message(message, chrono::system_clock::now(), B);

    octet hashMsg;

    octet temp1, temp2;
    octet msgMessage = msg->getMessage();
    octet msgTimestamp = msg->getTimestamp();
    Message::Concatenate_octet(&msgMessage, &msgTimestamp, &temp1);

    octet msgB = msg->getB();
    Message::Concatenate_octet(&temp1, &msgB, &temp2);

    Message::Hash_Function(HASH_TYPE_Ed25519, &temp2, &hashMsg);

    // Generate Signature --> signedMessage = SignatureKey + privateKey + randKey.getPrivateKey() * H(M || T || B)
    octet result;
    Message::add_octets(&privateKey, &signatureKey, &result); // signature Key + private Key
    octet part3;
    octet randKeyPrivateKey = randKey.getPrivateKey();
    Message::multiply_octet(&randKeyPrivateKey, &hashMsg, &part3); // b* H(M || T || B)

    Message::add_octets(&result, &part3, &signedMessage); // signature Key + private Key + b* H(M || T || B)

    msg->setFinalMsg(signedMessage);

    // print the signature
    cout << "Signature = ";
    OCT_output(&signedMessage);
    cout << endl;

    // Clean up
    free(temp1.val);
    free(temp2.val);
    delete[] randKeyPublicKey.val;
    delete[] result.val;
    delete[] part3.val;
    delete[] hashMsg.val;
    delete[] signedMessage.val;
    return true;
}

// static bool verifyMessage(bool ph, octet *publicKey, octet *context, octet *message, octet *signature)
// {
//     return EDDSA_VERIFY(ph, publicKey, context, message, signature);
// }

#define T_replay 1000

bool Vehicle::Validate_Message(Ed25519::ECP *GeneratorPoint, core::octet *signatureKey, core::octet *VehiclePublicKey, core::octet *A, Message msg)
{
    using namespace B256_56;

    // Retrieve the timestamp from the message as a 4-byte octet
    core::octet timestamp_oct = msg.getTimestamp();

    // Convert 4-byte octet to a 32-bit integer (milliseconds)
    uint32_t millis = 0;
    unsigned char *ptr = (unsigned char *)timestamp_oct.val;
    for (int i = 0; i < 4; i++)
    {
        millis <<= 8;
        millis |= ptr[i];
    }

    // Convert milliseconds since epoch to chrono::system_clock::time_point
    chrono::system_clock::time_point receivedTimestamp = chrono::system_clock::time_point(chrono::milliseconds(millis));

    auto now = chrono::system_clock::now();

    // Check for replay attack by comparing timestamps
    if (chrono::duration_cast<chrono::milliseconds>(now - receivedTimestamp).count() > T_replay)
    {
        cout << "Replay attack detected!" << endl;
        return false; // The message is too old, possible replay attack
    }

    ECP LHS, RHS, P, Apoint, Bpoint, SigKey, VehPubKey;

    // Convert octet to ECP
    ECP_fromOctet(&SigKey, signatureKey);
    ECP_fromOctet(&VehPubKey, VehiclePublicKey);
    ECP_fromOctet(&Apoint, A);
    octet msgB = msg.getB();
    ECP_fromOctet(&Bpoint, &msgB);

    // generate new variables to ensure original parameters are not changed

    ECP_copy(&P, GeneratorPoint); // P = Generator

    // Compute LHS = σ(M) * P

    BIG signedMessageHash;
    BIG_fromBytes(signedMessageHash, msg.getFinalMsg().val);
    ECP_mul(&P, signedMessageHash); // P = σ(M) * P
    ECP_copy(&LHS, &P);             // LHS =  P

    // Compute RHS = GK + H(PKi || A) * A + PKi + H(M || T || B) * B

    ECP_copy(&RHS, &SigKey);   // RHS = GK
    ECP_add(&RHS, &VehPubKey); // RHS = GK + PKi

    octet *r1 = new octet(), *r2 = new octet(), *temp = new octet();
    Message::Concatenate_octet(VehiclePublicKey, A, r1); // r1 = PKi || A --> Octet concatenation

    octet msgMessage = msg.getMessage();
    octet msgTimestamp = msg.getTimestamp();
    Message::Concatenate_octet(&msgMessage, &msgTimestamp, temp); // temp = M || T ||--> Octet concatenation

    Message::Concatenate_octet(temp, &msgB, r2); // r2 = M || T || B --> Octet concatenation

    octet *Hash_A = new octet, *Hash_B = new octet();
    Message::Hash_Function(HASH_TYPE_Ed25519, r1, Hash_A); // Hash_A = H(PKi || A)
    Message::Hash_Function(HASH_TYPE_Ed25519, r2, Hash_B); // Hash_B = H(M || T || B)

    // Convert Octet to BIG for Point multiplication
    BIG A_hash;
    BIG_fromBytes(A_hash, Hash_A->val);
    BIG B_hash;
    BIG_fromBytes(B_hash, Hash_B->val);

    ECP_mul(&Apoint, A_hash); // Apoint = H(PKi || A) * A
    ECP_mul(&Bpoint, B_hash); // Bpoint = H(M || T || B) * B

    ECP_add(&RHS, &Apoint); // RHS = GK + H(PKi || A) * A
    ECP_add(&RHS, &Bpoint); // RHS = GK + H(PKi || A) * A + H(M || T || B) * B

    // Compare LHS and RHS

    if (!ECP_equals(&LHS, &RHS))
    {
        cout << "Message has been Compromised\n";
        return false;
    }

    return true;
}
