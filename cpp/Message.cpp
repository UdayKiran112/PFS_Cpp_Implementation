#include <bits/stdc++.h>
#include "Message.h"
using namespace std;

Message::Message()
{
}

Message::~Message()
{
    // delete[] message.val;
    // delete[] Timestamp.val;
    // delete[] finalMsg.val;
}

Message::Message(string message, chrono::system_clock::time_point Timestamp, core::octet *B)
{
    this->message.len = message.size();
    this->message.max = message.size();
    this->message.val = new char[message.size()];
    memcpy(this->message.val, message.c_str(), message.size());

    timestamp_to_octet(Timestamp, &this->Timestamp);

    this->B = *B;
}

core::octet Message::getMessage()
{
    return message;
}

core::octet Message::getTimestamp()
{
    return Timestamp;
}

core::octet Message::getB()
{
    return B;
}

core::octet Message::getFinalMsg()
{
    return finalMsg;
}

void Message::setMessage(core::octet message)
{
    this->message = message;
}

void Message::setTimestamp(core::octet Timestamp)
{
    this->Timestamp = Timestamp;
}

void Message::setB(core::octet B)
{
    this->B = B;
}

void Message::setFinalMsg(core::octet finalMsg)
{
    this->finalMsg = finalMsg;
}

using namespace core;
using namespace Ed25519;
using namespace B256_56;
using namespace F25519;

void Message::Hash_Function(int hlen, octet *input, octet *output)
{
    char hash[128];
    octet H = {0, sizeof(hash), hash};

    // Perform hashing using the SPhash function
    SPhash(MC_SHA2, hlen, &H, input);

    // Store the hash in the output octet
    output->len = hlen;
    output->max = hlen;
    output->val = new char[hlen];
    memcpy(output->val, H.val, hlen);
}

void Message::Concatenate_octet(octet *data1, octet *data2, octet *result)
{
    int total_length = data1->len + data2->len;

    // Allocate memory for the new concatenated value
    result->val = (char *)malloc(total_length);
    if (!result->val)
    {
        throw std::bad_alloc(); // Throw if malloc fails
    }
    result->max = total_length;
    result->len = total_length;

    if (result->max < (data1->len + data2->len))
    {
        throw std::length_error("Not enough space in result octet");
    }

    // Copy data from the first octet into the output
    memcpy(result->val, data1->val, data1->len);

    // Copy data from the second octet into the output (after the first)
    memcpy(result->val + data1->len, data2->val, data2->len);
}

void Message::add_octets(octet *data1, octet *data2, octet *result)
{
    // Error checking
    if (!data1 || !data2 || !result)
    {
        throw std::invalid_argument("One or more octets are null");
    }

    // Ensure lengths are correct before proceeding
    if (data1->len != MODBYTES_B256_56 || data2->len != MODBYTES_B256_56)
    {
        throw std::length_error("Input octet lengths are invalid");
    }

    // Allocate memory for the result octet if not already allocated
    if (!result->val)
    {
        result->val = new char[MODBYTES_B256_56]; // Allocate memory for the result
        result->max = MODBYTES_B256_56;           // Set maximum size
    }

    BIG curve_order, point1, point2, sum;

    // Copy the curve order.
    BIG_rcopy(curve_order, CURVE_Order);

    // Convert the byte arrays from the octets into BIG integers.
    BIG_fromBytes(point1, data1->val);
    BIG_fromBytes(point2, data2->val);

    // Perform modular addition: sum = (point1 + point2) % curve_order.
    BIG_modadd(sum, point1, point2, curve_order);

    // Convert the resulting BIG back into a byte array.
    BIG_toBytes(result->val, sum);

    // Update the length of the result octet.
    result->len = MODBYTES_B256_56; // Set this to the correct length of the output (typically MODBYTES).
}

void Message::timestamp_to_octet(chrono::system_clock::time_point timeStamp, octet *result)
{
    using namespace chrono;

    // Check if the result is not null
    if (result == nullptr) {
        throw std::invalid_argument("Result octet must not be null");
    }

    // Deallocate existing memory if previously allocated
    if (result->val != nullptr) {
        delete[] result->val; // Free previously allocated memory
    }

    auto time_since_epoch = timeStamp.time_since_epoch();
    auto millis = duration_cast<milliseconds>(time_since_epoch).count();

    // Truncate to 32 bits (4 bytes)
    uint32_t truncated_millis = static_cast<uint32_t>(millis);

    // Allocate memory for 4 bytes
    result->len = 4;
    result->max = 4;
    result->val = new char[4];
    
    if (result->val == nullptr) {
        throw std::runtime_error("Memory allocation failed");
    }

    unsigned char *ptr = reinterpret_cast<unsigned char *>(result->val);

    // Store the 32-bit (4-byte) truncated value into the octet
    for (int i = 3; i >= 0; i--) {
        ptr[i] = truncated_millis & 0xFF;
        truncated_millis >>= 8;
    }
}


void Message::multiply_octet(octet *data1, octet *data2, octet *result)
{
    BIG point1, point2, product;

    if (!data1 || !data1->val || data1->len <= 0)
    {
        throw std::invalid_argument("data1 is invalid");
    }
    if (!data2 || !data2->val || data2->len <= 0)
    {
        throw std::invalid_argument("data2 is invalid");
    }

    BIG_fromBytes(point1, data1->val);
    BIG_fromBytes(point2, data2->val);
    BIG_mul(product, point1, point2);
    result->len = 32;
    result->max = 32;
    result->val = new char[32];
    BIG_toBytes(result->val, product);
}