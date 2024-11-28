#include <bits/stdc++.h>
#include "Lib/core.h"
#include "Vehicle.h"
#include "Message.h"
using namespace std;

// using namespace core;

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

    // octet privateKey;
    Ed25519::ECP generator;
    Key::PointGeneration(&generator);

    TA ta = TA(&RNG);
    Vehicle vehicle = Vehicle(&RNG, ta);

    // initilize an octet with a static integer in it
    octet reg = {0, 4, (char *)"1234"};
    // output the octet reg
    OCT_output(&reg);
    vehicle.setRegistrationId(reg); // for testing purposes
    vehicle.requestVerification(&RNG);

    Message msg;
    char pub[2 * EFS_Ed25519 + 1];
    octet B = {0, sizeof(pub), pub};
    string message = "Mugiwara";
    vehicle.signMessage(&RNG, message, &B, &msg);

    // verification by the receiver
    Vehicle receiverVehicle = Vehicle(&RNG, ta);
    octet vehicleSignKey = vehicle.getSignatureKey();

    cout << "Sender Vehicle Signature Key= ";
    OCT_output(&vehicleSignKey);
    cout << endl;

    octet vehiclePubKey = vehicle.getVehicleKey().getPublicKey();
    octet Ap = vehicle.getA();
    receiverVehicle.Validate_Message(&generator, &vehicleSignKey, &vehiclePubKey, &Ap, msg);

    // clean up
    delete[] vehiclePubKey.val;
    delete[] msg.getMessage().val;
    delete[] msg.getB().val;

    return 0;
}