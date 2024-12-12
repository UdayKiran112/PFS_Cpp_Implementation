#include <iostream>
#include <chrono>
#include <fstream>
#include <iomanip> // For std::setprecision
#include "Message.h"
#include "Vehicle.h"
#include "Key.h"
#include "TA.h"
#include "Lib/core.h"

using namespace std;
using namespace std::chrono;

// ANSI escape codes for colored output
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"

void measureHashingTime(Message &msg, const string &message)
{
    octet hashMsg;
    auto start = high_resolution_clock::now();
    auto messageContent = msg.getMessage();
    msg.Hash_Function(HASH_TYPE_Ed25519, &messageContent, &hashMsg);
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();
    cout << CYAN << "Hashing Time: " << duration << " microseconds" << RESET << endl;

    delete[] hashMsg.val;
}

void measureSigningTime(Vehicle &vehicle, csprng *RNG, const string &message, octet *B, Message *msg)
{
    auto start = high_resolution_clock::now();
    vehicle.signMessage(RNG, message, B, msg);
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();
    cout << GREEN << "Signing Time: " << duration << " microseconds" << RESET << endl;
}

void measureValidationTime(Vehicle &receiverVehicle, Ed25519::ECP *generator,
                           octet *vehicleSignKey, octet *vehiclePubKey, octet *Ap, Message &msg)
{
    auto start = high_resolution_clock::now();
    receiverVehicle.Validate_Message(generator, vehicleSignKey, vehiclePubKey, Ap, &msg);
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();
    cout << YELLOW << "Validation Time: " << duration << " microseconds" << RESET << endl;
}

void measureScalarMultiplicationTime(Ed25519::ECP *point, B256_56::BIG scalar)
{
    auto start = high_resolution_clock::now();
    Ed25519::ECP_mul(point, scalar);
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();
    cout << MAGENTA << "Scalar Multiplication Time: " << duration << " microseconds" << RESET << endl;
}

void measurePointAdditionTime(Ed25519::ECP *point1, Ed25519::ECP *point2)
{
    auto start = high_resolution_clock::now();
    Ed25519::ECP_add(point1, point2);
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();
    cout << BLUE << "Point Addition Time: " << duration << " microseconds" << RESET << endl;
}

int main()
{
    ofstream nullStream;
    streambuf* originalCoutBuffer = cout.rdbuf(nullStream.rdbuf());

    unsigned long ran;
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    csprng RNG;
    time((time_t *)&ran);
    RAW.len = 100;
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (int i = 4; i < 100; i++)
        RAW.val[i] = i;
    CREATE_CSPRNG(&RNG, &RAW);

    // Initialize objects
    Ed25519::ECP generator;
    Key::PointGeneration(&generator);

    TA ta = TA(&RNG);
    Vehicle vehicle = Vehicle(&RNG, ta);

    // Initialize an octet with a static integer in it
    octet reg = {0, 4, (char *)"1234"};
    vehicle.setRegistrationId(reg); // for testing purposes
    vehicle.requestVerification(&RNG);

    Message msg;
    char pub[2 * EFS_Ed25519 + 1];
    octet B = {0, sizeof(pub), pub};
    string message = "Mugiwara";

    cout.rdbuf(originalCoutBuffer);

    const int iterations = 100;
    double totalHashingTime = 0.0;
    double totalSigningTime = 0.0;
    double totalValidationTime = 0.0;
    double totalScalarMultiplicationTime = 0.0;
    double totalPointAdditionTime = 0.0;

    for (int i = 0; i < iterations; ++i) {
        cout << "----------------------------------------" << endl;
        cout << "Iteration " << i + 1 << " of " << iterations << endl;
        cout << "----------------------------------------" << endl;

        auto start = high_resolution_clock::now();
        measureHashingTime(msg, message);
        auto end = high_resolution_clock::now();
        totalHashingTime += duration_cast<duration<double, std::milli>>(end - start).count();

        start = high_resolution_clock::now();
        measureSigningTime(vehicle, &RNG, message, &B, &msg);
        end = high_resolution_clock::now();
        totalSigningTime += duration_cast<duration<double, std::milli>>(end - start).count();

        B256_56::BIG scalar;
        B256_56::BIG_random(scalar, &RNG);
        start = high_resolution_clock::now();
        measureScalarMultiplicationTime(&generator, scalar);
        end = high_resolution_clock::now();
        totalScalarMultiplicationTime += duration_cast<duration<double, std::milli>>(end - start).count();

        Ed25519::ECP point1 = generator; // Copy generator for testing addition
        Ed25519::ECP point2 = generator; // Copy generator for testing addition
        start = high_resolution_clock::now();
        measurePointAdditionTime(&point1, &point2);
        end = high_resolution_clock::now();
        totalPointAdditionTime += duration_cast<duration<double, std::milli>>(end - start).count();

        Vehicle receiverVehicle = Vehicle(&RNG, ta);
        octet vehicleSignKey = vehicle.getSignatureKey();
        octet vehiclePubKey = vehicle.getVehicleKey().getPublicKey();
        octet Ap = vehicle.getA();

        start = high_resolution_clock::now();
        measureValidationTime(receiverVehicle, &generator, &vehicleSignKey, &vehiclePubKey, &Ap, msg);
        end = high_resolution_clock::now();
        totalValidationTime += duration_cast<duration<double, std::milli>>(end - start).count();

        delete[] vehiclePubKey.val;
        delete[] msg.getMessage().val;
        delete[] msg.getB().val;

        cout << endl; // Add spacing between iterations
    }

    cout.rdbuf(originalCoutBuffer);

    cout << fixed << setprecision(4);
    cout << "Average Hashing Time: " << totalHashingTime / iterations << " milliseconds" << endl;
    cout << "Average Signing Time: " << totalSigningTime / iterations << " milliseconds" << endl;
    cout << "Average Scalar Multiplication Time: " << totalScalarMultiplicationTime / iterations << " milliseconds" << endl;
    cout << "Average Point Addition Time: " << totalPointAdditionTime / iterations << " milliseconds" << endl;
    cout << "Average Validation Time: " << totalValidationTime / iterations << " milliseconds" << endl;

    KILL_CSPRNG(&RNG);

    return 0;
}
