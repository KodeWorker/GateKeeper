#include "gatekeeper.hpp"
#include "private_key.h"

GateKeeper::GateKeeper()
{

}

GateKeeper::~GateKeeper()
{

}

void GateKeeper::GenerateSL(Config config, std::string path)
{

}

bool GateKeeper::ActivateSL(std::string path)
{

}

bool GateKeeper::VerifySL(std::string path)
{

}

bool GateKeeper::LoadPrivateKey()
{
    std::vector<char> char_vector;
    for(int i = 0; i < RESOURCE_PRIVATE_KEY_len; i++)
    {
        char_vector.push_back(RESOURCE_PRIVATE_KEY[i]);
    }
    private_key = std::string(char_vector.begin(), char_vector.end());
}

bool GateKeeper::GeneratePublicKey()
{

}

bool GateKeeper::DurationCheck()
{

}

bool GateKeeper::ExecutionCountCheck()
{

}

std::pair<std::string, Config> GateKeeper::ParseSL(std::string path)
{

}
