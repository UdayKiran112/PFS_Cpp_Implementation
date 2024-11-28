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

Vehicle::~Vehicle()
{
    delete[] A.val;
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
    char *pub = new char[2 * EFS_Ed25519 + 1];
    octet virpubkey = {0, sizeof(pub), pub};

    // Create a copy of the public key before using it
    octet publicKey = this->getVehicleKey().getPublicKey();
    char *pk_copy = new char[publicKey.len];
    memcpy(pk_copy, publicKey.val, publicKey.len);
    octet pk_octet = {publicKey.len, publicKey.max, pk_copy};

    auto temp = this->registrationId;
    this->ta.validateRequest(RNG, &temp, &pk_octet, &signkey, &virpubkey);

    char *a_val = new char[virpubkey.len];
    memcpy(a_val, virpubkey.val, virpubkey.len);
    octet a = {virpubkey.len, virpubkey.max, a_val};

    this->setSignatureKey(signkey);
    this->setA(a);

    // clean up
    delete[] pub;
    delete[] pk_copy;
    delete[] publicKey.val;
    delete[] virpubkey.val;
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

    auto ts = std::chrono::system_clock::now();

    // Print timestamp
    std::time_t timeT = std::chrono::system_clock::to_time_t(ts);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(ts.time_since_epoch()).count() % 1000;
    std::tm localTm = *std::localtime(&timeT);
    std::cout << "Timestamp in signMessage = "
              << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S")
              << "." << std::setfill('0') << std::setw(3) << ms << std::endl;
    cout << endl;

    // Set the full message
    msg->setFullMessage(message, ts, B);

    octet hashMsg;

    octet temp1, temp2;
    octet msgMessage = msg->getMessage();

    // Create a temporary octet for timestamp
    char timestamp_val[4]; // 4 bytes for uint32_t
    octet timestamp_oct = {sizeof(timestamp_val), sizeof(timestamp_val), timestamp_val};

    // Convert timestamp to octet using the Message class helper
    Message::timestamp_to_octet(ts, &timestamp_oct); // Use the same conversion method as in Message class

    cout << "Timestamp in octet in signMessage: ";
    OCT_output(&timestamp_oct);
    cout << endl;

    temp1.len = msgMessage.len + timestamp_oct.len;
    temp1.max = msgMessage.max + timestamp_oct.max + B->max;
    temp1.val = new char[temp1.max];
    Message::Concatenate_octet(&msgMessage, &timestamp_oct, &temp1);

    // Allocate space for B
    char b_val[2 * EFS_Ed25519 + 1];
    octet msgB = {0, sizeof(b_val), b_val};
    msgB = msg->getB();

    temp2.len = temp1.len + msgB.len;
    temp2.max = temp1.max;
    temp2.val = new char[temp2.max];
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
    delete[] temp1.val;
    delete[] temp2.val;
    delete[] result.val;
    delete[] part3.val;
    delete[] hashMsg.val;
    delete[] signedMessage.val;
    delete[] randKeyPublicKey.val;
    delete[] timestamp_oct.val;

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

    // Create a temporary octet for timestamp
    char timestamp_val[8]; // Change to 8 bytes to accommodate full timestamp
    octet timestamp_oct = {sizeof(timestamp_val), sizeof(timestamp_val), timestamp_val};

    // Get timestamp from message and convert to octet using the same method
    auto timestamp = msg.getTimestamp();
    Message::timestamp_to_octet(timestamp, &timestamp_oct);

    // Convert the octet back to time_point - Update this section
    int64_t received_timestamp_ms; // Change to 64-bit integer for milliseconds
    memcpy(&received_timestamp_ms, timestamp_oct.val, sizeof(received_timestamp_ms));

    // Create time_point from milliseconds since epoch
    chrono::system_clock::time_point receivedTimestamp = 
        chrono::system_clock::time_point(chrono::milliseconds(received_timestamp_ms));

    auto now = chrono::system_clock::now();

    // Log the timestamps for debugging
    std::time_t receivedTimeT = std::chrono::system_clock::to_time_t(receivedTimestamp);
    auto receivedMs = std::chrono::duration_cast<std::chrono::milliseconds>(receivedTimestamp.time_since_epoch()).count() % 1000;
    std::tm receivedLocalTm = *std::localtime(&receivedTimeT);
    std::cout << "Received Timestamp = "
              << std::put_time(&receivedLocalTm, "%Y-%m-%d %H:%M:%S")
              << "." << std::setfill('0') << std::setw(3) << receivedMs << std::endl;

    std::time_t nowTimeT = std::chrono::system_clock::to_time_t(now);
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
    std::tm nowLocalTm = *std::localtime(&nowTimeT);
    std::cout << "Current Timestamp = "
              << std::put_time(&nowLocalTm, "%Y-%m-%d %H:%M:%S")
              << "." << std::setfill('0') << std::setw(3) << nowMs << std::endl;

    // Check for replay attack by comparing timestamps
    if (chrono::duration_cast<chrono::milliseconds>(now - receivedTimestamp).count() > T_replay)
    {
        cout << "Replay attack detected!" << endl;
        return false; // The message is too old, possible replay attack
    }

    ECP LHS, RHS, P, Apoint, Bpoint, SigKey, VehPubKey;

    // Get B from message first
    char b_val[2 * EFS_Ed25519 + 1];        // Allocate space for B value
    octet msgB = {0, sizeof(b_val), b_val}; // Initialize octet properly
    msgB = msg.getB();                      // Get B value from message

    // Add null checks before using ECP_fromOctet
    if (!signatureKey || !VehiclePublicKey || !A || !msgB.val)
    {
        cout << "Invalid input parameters - null pointer detected" << endl;
        return false;
    }

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

    char *r1_val = new char[VehiclePublicKey->len + A->len];
    octet r1 = {0, VehiclePublicKey->len + A->len, r1_val};
    Message::Concatenate_octet(VehiclePublicKey, A, &r1); // r1 = PKi || A --> Octet concatenation

    octet msgMessage = msg.getMessage();

    // Allocate new memory for temp
    char *temp_val = new char[msgMessage.len + timestamp_oct.len];
    octet temp = {0, (int)(msgMessage.len + timestamp_oct.len), temp_val};
    Message::Concatenate_octet(&msgMessage, &timestamp_oct, &temp); // temp = M || T ||--> Octet concatenation

    // Allocate new memory for r2
    char *r2_val = new char[temp.len + msgB.len];
    octet r2 = {0, (int)(temp.len + msgB.len), r2_val};

    Message::Concatenate_octet(&temp, &msgB, &r2); // r2 = M || T || B --> Octet concatenation

    // allocate space for Hash_A and Hash_B
    char hash_A_val[2 * EFS_Ed25519 + 1];
    octet Hash_A = {0, sizeof(hash_A_val), hash_A_val};
    char hash_B_val[3 * EFS_Ed25519 + 1];
    octet Hash_B = {0, sizeof(hash_B_val), hash_B_val};

    Message::Hash_Function(HASH_TYPE_Ed25519, &r1, &Hash_A); // Hash_A = H(PKi || A)
    Message::Hash_Function(HASH_TYPE_Ed25519, &r2, &Hash_B); // Hash_B = H(M || T || B)

    // Convert Octet to BIG for Point multiplication
    BIG A_hash;
    BIG_fromBytes(A_hash, Hash_A.val); // Use . instead of ->
    BIG B_hash;
    BIG_fromBytes(B_hash, Hash_B.val); // Use . instead of ->

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
    else
    {
        cout << endl;
        cout << "Vehicle Validated the Message\n";
    }

    // clean up
    delete[] Hash_A.val;
    delete[] Hash_B.val;
    delete[] r1_val;
    delete[] temp_val;
    delete[] r2_val;
    delete[] timestamp_oct.val;

    return true;
}
