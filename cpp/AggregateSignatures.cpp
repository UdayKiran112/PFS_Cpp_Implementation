#include <vector>
#include <iostream>
#include "Vehicle.h"
#include "TA.h"
#include "Message.h"
#include "Lib/core.h"

using namespace std;

// Function to initialize vehicles
vector<Vehicle> initializeVehicles(int numVehicles, csprng *RNG, TA &ta)
{
    vector<Vehicle> vehicles;
    vehicles.reserve(numVehicles); // Pre-allocate space to avoid reallocations

    for (int i = 0; i < numVehicles; ++i)
    {
        cout << "\n================ Vehicle " << i + 1 << " Operations ================\n";
        vehicles.emplace_back(RNG, ta);     // Construct Vehicle directly in the vector
        Vehicle &vehicle = vehicles.back(); // Get reference to the newly created vehicle

        cout << "Vehicle created successfully\n";
        octet reg = {0, 4, (char *)"1234"}; // Example registration ID
        vehicle.setRegistrationId(reg);
        cout << "Registration ID for Vehicle " << i + 1 << " set successfully\n";
        vehicle.requestVerification(RNG);
        cout << "Verification request for Vehicle " << i + 1 << " sent successfully\n";
    }
    return vehicles;
}

// Function to aggregate signatures
octet aggregateSignatures(const vector<octet> &signatures)
{
    octet aggregateSignature = {0, 0, nullptr};
    // Combine all signatures into one
    for (const auto &sig : signatures)
    {
        // Placeholder for actual aggregation logic
        // aggregateSignature = aggregate(aggregateSignature, sig);
    }
    return aggregateSignature;
}

// Function to verify the aggregate signature
bool verifyAggregateSignature(const octet &aggregateSignature, const vector<octet> &publicKeys, const vector<string> &messages)
{
    for (size_t i = 0; i < publicKeys.size(); ++i)
    {
        // Placeholder for actual verification logic
        // if (!verify(publicKeys[i], messages[i], aggregateSignature)) {
        //     return false;
        // }
    }
    return true;
}

// Main function to demonstrate the process
int main()
{
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

    Ed25519::ECP generator;
    Key::PointGeneration(&generator);

    TA ta(&RNG);
    int numVehicles;

    // Prompt user for the number of vehicles
    cout << "Enter the number of vehicles: ";
    cin >> numVehicles;

    // Initialize vehicles
    vector<Vehicle> vehicles = initializeVehicles(numVehicles, &RNG, ta);

    // Generate signatures using signMessage directly
    vector<octet> signatures;
    vector<Message> messages; // Store Message objects
    vector<string> vehicleMessages; // Store individual messages for each vehicle
    messages.reserve(numVehicles);
    signatures.reserve(numVehicles);
    vehicleMessages.reserve(numVehicles);

    for (int i = 0; i < numVehicles; ++i)
    {
        cout << "\n================ Vehicle " << i + 1 << " Signature Generation ================\n";

        // Initialize B
        char b_val[2 * EFS_Ed25519 + 1];
        octet B = {0, sizeof(b_val), b_val};

        // Create unique message for each vehicle (example)
        string vehicleMessage = "Message_from_Vehicle_" + to_string(i + 1);
        vehicleMessages.push_back(vehicleMessage);

        // Create Message object
        Message msg;

        // Sign the message
        octet signature; // Declare the signature variable
        if (vehicles[i].signMessage(&RNG, vehicleMessage, &B, &msg, &signature))
        {
            // Get the final message and create a deep copy
            const octet &finalMsg = msg.getFinalMsg();
            char* newVal = new char[finalMsg.len];
            memcpy(newVal, finalMsg.val, finalMsg.len);
            
            // Create new octet with copied data
            octet signatureCopy = {0, finalMsg.len, newVal};
            signatures.push_back(signatureCopy);
            
            cout << "Signature generated successfully for Vehicle " << i + 1 << "\n";
        }
        else
        {
            cout << "Failed to generate signature for Vehicle " << i + 1 << "\n";
        }
    }

    // Aggregate signatures
    octet aggregateSignature = aggregateSignatures(signatures);

    // Prepare public keys for verification
    vector<octet> publicKeys;
    for (const auto &vehicle : vehicles)
    {
        octet pubKey = vehicle.getVehicleKey().getPublicKey();
        publicKeys.push_back(pubKey);
    }

    // Verify aggregate signature
    bool isValid = verifyAggregateSignature(aggregateSignature, publicKeys, vehicleMessages);
    if (isValid)
    {
        cout << "Aggregate signature is valid." << endl;
    }
    else
    {
        cout << "Aggregate signature is invalid." << endl;
    }

    // Verification by the receiver
    Vehicle receiverVehicle(&RNG, ta);
    octet vehicleSignKey = vehicles[0].getSignatureKey();

    cout << "Sender Vehicle Signature Key= ";
    OCT_output(&vehicleSignKey);
    cout << endl;

    octet vehiclePubKey = vehicles[0].getVehicleKey().getPublicKey();
    octet Ap = vehicles[0].getA();
    Message verificationMsg;
    octet signature; // Declare the signature variable
    vehicles[0].signMessage(&RNG, vehicleMessages[0], &publicKeys[0], &verificationMsg, &signature);

    receiverVehicle.Validate_Message(&generator, &vehicleSignKey, &vehiclePubKey, &Ap, verificationMsg);

    // Cleanup signatures vector
    for (auto &sig : signatures) {
        if (sig.val != nullptr) {
            delete[] sig.val;
            sig.val = nullptr;
        }
    }
    signatures.clear();

    // Cleanup
    // Clean up public keys
    for (auto &key : publicKeys)
    {
        if (key.val != nullptr)
        {
            delete[] key.val;
            key.val = nullptr; // Set to nullptr to avoid double-free
        }
    }

    // Clean up remaining octets
    if (vehiclePubKey.val != nullptr)
    {
        delete[] vehiclePubKey.val;
        vehiclePubKey.val = nullptr; // Set to nullptr to avoid double-free
    }
    if (aggregateSignature.val != nullptr)
    {
        delete[] aggregateSignature.val;
        aggregateSignature.val = nullptr; // Set to nullptr to avoid double-free
    }

    KILL_CSPRNG(&RNG);

    return 0;
}