#include <iostream>
#include <cstring>
#include "Lib/core.h"
using namespace core;

// Function to concatenate two octets into a result octet
bool concatenate_octets(octet *octet1, octet *octet2, octet *result)
{
    // Calculate the total length required
    int total_len = octet1->len + octet2->len;

    // Check if result has enough space
    if (result->max < total_len)
    {
        std::cerr << "Error: result octet does not have enough space to hold concatenated data." << std::endl;
        return false;
    }

    // Copy data from octet1 to result  
    std::memcpy(result->val, octet1->val, octet1->len);

    // Copy data from octet2 to result after octet1
    std::memcpy(result->val + octet1->len, octet2->val, octet2->len);

    // Set the new length of the result octet
    result->len = total_len;

    return true;
}

int main()
{
    char buffer1[10] = "Hello";
    char buffer2[10] = "World";

    octet octet1 = {5, sizeof(buffer1), buffer1};
    octet octet2 = {5, sizeof(buffer2), buffer2};

    std::cout << "Octet1: " << std::endl;
    OCT_output(&octet1); // Expected output: Hello
    std::cout << std::endl;

    std::cout << "Octet2: " << std::endl;
    OCT_output(&octet2); // Expected output: World
    std::cout << std::endl;

    char result_buffer[20];
    octet result = {0, sizeof(result_buffer), result_buffer};

    if (concatenate_octets(&octet1, &octet2, &result))
    {
        std::cout << "Result: " << std::endl;
        OCT_output(&result); // Expected output: HelloWorld
        std::cout << std::endl;
    }

    return 0;
}
