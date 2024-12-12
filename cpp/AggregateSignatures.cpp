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

    try {
        for (int i = 0; i < numVehicles; ++i)
        {
            cout << "\n================ Vehicle " << i + 1 << " Operations ================\n";
            
            // Create vehicle with RNG and TA
            Vehicle vehicle(RNG, ta);     

            cout << "Vehicle created successfully\n";
            
            // Use a stack-allocated registration ID to avoid dynamic memory issues
            octet reg = {0, 4, (char *)"1234"}; 
            vehicle.setRegistrationId(reg);
            
            cout << "Registration ID for Vehicle " << i + 1 << " set successfully\n";
            
            try {
                // Wrap requestVerification in a separate try-catch to isolate potential errors
                vehicle.requestVerification(RNG);
                vehicles.push_back(std::move(vehicle)); // Use move semantics
            }
            catch (const std::exception& verifyError) {
                cerr << "Error in vehicle verification: " << verifyError.what() << endl;
                // Continue to next vehicle instead of aborting entire process
                continue;
            }
        }
    }
    catch (const std::exception& e) {
        cerr << "Error in vehicle initialization: " << e.what() << endl;
        vehicles.clear(); // Ensure cleanup
    }

    if (vehicles.empty()) {
        throw std::runtime_error("No vehicles could be initialized");
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

    try {
        // Initialize vehicles
        vector<Vehicle> vehicles = initializeVehicles(numVehicles, &RNG, ta);

        // Check if vehicles were successfully created
        if (vehicles.empty()) {
            cerr << "Failed to create vehicles" << endl;
            return 1;
        }

        // Generate signatures using signMessage directly
        vector<octet> signatures;
        vector<Message> messages;       // Store Message objects
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
            if (vehicles[i].signMessage(&RNG, vehicleMessage, &B, &msg))
            {
                // Directly get the final message (signature) from the Message object
                const octet &finalMsg = msg.getFinalMsg();

                // Copy the signature data into a new array
                char sigVal[finalMsg.len];
                memcpy(sigVal, finalMsg.val, finalMsg.len);

                // Create new octet with copied data
                octet signatureCopy = {finalMsg.len, finalMsg.len, sigVal};
                signatures.push_back(signatureCopy);

                // Print the signature for verification
                cout << "Signature for Vehicle " << i + 1 << ": ";
                OCT_output(&signatureCopy);
                cout << endl;
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

        // Cleanup signatures vector
        for (auto &sig : signatures)
        {
            if (sig.val != nullptr)
            {
                delete[] sig.val;
                sig.val = nullptr;
            }
        }
        signatures.clear();

        // Additional cleanup for other dynamically allocated resources
        for (auto &key : publicKeys)
        {
            if (key.val != nullptr)
            {
                delete[] key.val;
                key.val = nullptr;
            }
        }
    }
    catch (const std::exception& e) {
        cerr << "Unhandled exception: " << e.what() << endl;
        return 1;
    }
    
    // Ensure cleanup of RNG
    KILL_CSPRNG(&RNG);
    return 0;
}
