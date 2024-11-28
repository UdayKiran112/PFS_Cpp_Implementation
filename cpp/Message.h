#pragma once

#include <bits/stdc++.h>
#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include <chrono>
#include "Lib/core.h"
#include "Lib/eddsa_Ed25519.h"
#include "Lib/config_big_B256_56.h"
using namespace std;

class Message
{
private:
    core::octet message;
    std::chrono::system_clock::time_point timestamp;
    core::octet B; // Public Key Type
    // core::octet hashMsg; //64 bitss less than multiple of 512 bits
    core::octet finalMsg;
    std::chrono::system_clock::time_point Timestamp;

public:
    Message();
    ~Message();
    void setFullMessage(string message, std::chrono::system_clock::time_point timestamp, core::octet *B);
    core::octet getMessage();
    std::chrono::system_clock::time_point getTimestamp();
    const core::octet &getB();
    // core::octet getHashMsg();
    core::octet getFinalMsg();
    void setMessage(core::octet message);
    void setTimestamp(std::chrono::system_clock::time_point timestamp);
    void setB(core::octet B);
    // void setHashMsg(core::octet hashMsg);
    void setFinalMsg(core::octet finalMsg);

    static void Concatenate_octet(octet *data1, octet *data2, octet *result);
    static void Hash_Function(int hlen, octet *input, octet *output);
    static void add_octets(octet *data1, octet *data2, octet *result);
    static void multiply_octet(octet *data1, octet *data2, octet *result);
    static void timestamp_to_octet(std::chrono::system_clock::time_point timeStamp, octet *result);
};

#endif // MESSAGE_H