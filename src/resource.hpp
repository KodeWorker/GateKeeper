#ifndef RESOURCE_HPP
#define RESOURCE_HPP

#include <string>
#include <vector>
#include "private_key.h"

std::string GetPrivateKey()
{
    std::vector<char> char_vector;
    for(int i = 0; i < RESOURCE_PRIVATE_KEY_len; i++)
    {
        char_vector.push_back(RESOURCE_PRIVATE_KEY[i]);
    }
    return std::string(char_vector.begin(), char_vector.end());
}


std::string GetPublicKey()
{
    std::vector<char> char_vector;
    for(int i = 0; i < RESOURCE_PUBLIC_KEY_len; i++)
    {
        char_vector.push_back(RESOURCE_PUBLIC_KEY[i]);
    }
    return std::string(char_vector.begin(), char_vector.end());
}

#endif // RESOURCE_HPP