#include <bits/stdc++.h>
#include "Message.h"
using namespace std;

Message::Message()
{
}

Message::~Message()
{
    // if (message.val) {
    //     delete[] message.val;
    //     message.val = nullptr;
    // }
    // if (Timestamp.val) {
    //     delete[] Timestamp.val;
    //     Timestamp.val = nullptr;
    // }
    // if (B.val)
    // {
    //     delete[] B.val;
    //     B.val = nullptr;
    // }
    // if (finalMsg.val) {
    //     delete[] finalMsg.val;
    //     finalMsg.val = nullptr;
    // }
}

void Message::setFullMessage(string message, chrono::system_clock::time_point Timestamp, core::octet *B)
{
    this->message.len = message.size();
    this->message.max = message.size();
    this->message.val = new char[message.size()];
    memcpy(this->message.val, message.c_str(), message.size());

    this->Timestamp = Timestamp;

    // Properly initialize B octet before copying
    if (B != nullptr && B->val != nullptr)
    {
        this->B.len = B->len;
        this->B.max = B->len;
        this->B.val = new char[B->len];
        OCT_copy(B, &this->B);
    }
    else
    {
        this->B.len = 0;
        this->B.max = 0;
        this->B.val = nullptr;
    }
}

core::octet Message::getMessage()
{
    return message;
}

chrono::system_clock::time_point Message::getTimestamp()
{
    return Timestamp;
}

const core::octet &Message::getB()
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

void Message::setTimestamp(chrono::system_clock::time_point Timestamp)
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
    // Add input validation
    if (!data1 || !data2 || !result || !data1->val || !data2->val)
    {
        throw std::invalid_argument("Invalid input octets");
    }

    int total_length = data1->len + data2->len;

    // Allocate new memory for result if needed
    if (!result->val || result->max < total_length)
    {
        delete[] result->val; // Delete old memory if it exists
        result->val = new char[total_length];
        result->max = total_length;
    }

    // Use memmove instead of memcpy to handle overlapping memory
    memmove(result->val, data1->val, data1->len);
    memmove(result->val + data1->len, data2->val, data2->len);

    // Set the length of the output
    result->len = total_length;
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
    if (result == nullptr)
    {
        throw std::invalid_argument("Result octet cannot be null");
    }

    using namespace chrono;

    // Convert to milliseconds since epoch
    auto timestamp_ms = duration_cast<milliseconds>(timeStamp.time_since_epoch()).count();

    // Use uint64_t to store milliseconds to maintain precision
    uint64_t ms_value = static_cast<uint64_t>(timestamp_ms);

    // Allocate new memory
    result->val = new char[sizeof(ms_value)];
    result->max = sizeof(ms_value);

    // Store the full 8 bytes
    memcpy(result->val, &ms_value, sizeof(ms_value));
    result->len = sizeof(ms_value);
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